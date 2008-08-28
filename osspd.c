/*
 * osspd - OSS Proxy Daemon: emulate OSS device using CUSE
 *
 * Copyright (C) 2008       SUSE Linux Products GmbH
 * Copyright (C) 2008       Tejun Heo <teheo@suse.de>
 *
 * This file is released under the GPLv2.
 */

#define FUSE_USE_VERSION 29
#define _GNU_SOURCE

#include <assert.h>
#include <cuse.h>
#include <cuse_lowlevel.h>
#include <fcntl.h>
#include <fuse_opt.h>
#include <libgen.h>
#include <limits.h>
#include <pthread.h>
#include <pwd.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <sys/stat.h>
#include <sys/epoll.h>
#include <sys/soundcard.h>
#include <unistd.h>

#include "ossp.h"
#include "ossp-util.h"

#define DFL_MIXER_NAME		"mixer"
#define DFL_DSP_NAME		"dsp"
#define DFL_ADSP_NAME		"adsp"
#define STRFMT			"S[%"PRIu64"/%d]"
#define STRID(os)		os->id, os->pid

#define dbg1_os(os, fmt, args...)	dbg1(STRFMT" "fmt, STRID(os) , ##args)
#define dbg0_os(os, fmt, args...)	dbg0(STRFMT" "fmt, STRID(os) , ##args)
#define warn_os(os, fmt, args...)	warn(STRFMT" "fmt, STRID(os) , ##args)
#define err_os(os, fmt, args...)	err(STRFMT" "fmt, STRID(os) , ##args)
#define warn_ose(os, err, fmt, args...)	\
	warn_e(err, STRFMT" "fmt, STRID(os) , ##args)
#define err_ose(os, err, fmt, args...)	\
	err_e(err, STRFMT" "fmt, STRID(os) , ##args)

enum {
	SNDRV_OSS_VERSION	= ((3<<16)|(8<<8)|(1<<4)|(0)),	/* 3.8.1a */
	DFL_MIXER_MAJOR		= 14,
	DFL_MIXER_MINOR		= 0,
	DFL_DSP_MAJOR		= 14,
	DFL_DSP_MINOR		= 3,
	DFL_ADSP_MAJOR		= 14,
	DFL_ADSP_MINOR		= 12,
	DFL_MAX_STREAMS		= 256,
};

struct ossp_uid_cnt {
	struct list_head	link;
	uid_t			uid;
	unsigned		nr_os;
};

struct ossp_mixer {
	pid_t			pgrp;
	struct list_head	link;
	unsigned		refcnt;
	/* the following two fields are protected by mixer_mutex */
	int			vol[2][2];
	int			modify_counter;
};

struct ossp_mixer_cmd {
	struct ossp_mixer	*mixer;
	struct ossp_mixer_arg	get;
	struct ossp_mixer_arg	set;
	int			nr_gets;
	int			out_dir;
	void			*out_buf;
	size_t			*out_bufszp;
};

#define for_each_vol(i, j)						\
	for (i = 0, j = 0; i < 2; j += i << 1, j++, i = j >> 1, j &= 1)

struct ossp_stream {
	uint64_t		id;	/* stream ID, also CUSE file handle */
	struct list_head	link;
	struct list_head	pgrp_link;
	struct list_head	notify_link;
	unsigned		refcnt;

	/* stream owner info */
	pid_t			pid;
	pid_t			pgrp;
	uid_t			uid;
	gid_t			gid;

	/* slave info */
	pthread_mutex_t		cmd_mutex;
	pid_t			slave_pid;
	int			cmd_fd;
	int			reply_fd;
	int			notify_tx;
	int			notify_rx;

	/* the following dead flag is set asynchronously, keep it separate. */
	int			dead;

	struct ossp_uid_cnt	*ucnt;
	struct fuse		*fuse;	/* associated fuse instance */
	struct ossp_mixer	*mixer;
};

struct ossp_dsp_stream {
	struct ossp_stream	os;
	unsigned		nonblock_set:1;
	unsigned		nonblock:1;
};

#define os_to_dsps(_os)		container_of(_os, struct ossp_dsp_stream, os)

static unsigned max_streams;
static unsigned umax_streams;
static unsigned hashtbl_size;
static char dsp_slave_path[PATH_MAX];

static pthread_mutex_t mutex = PTHREAD_MUTEX_INITIALIZER;
static pthread_mutex_t mixer_mutex = PTHREAD_MUTEX_INITIALIZER;
static uint64_t os_id;
static unsigned nr_os;
static struct list_head *mixer_tbl;	/* indexed by PGRP */
static struct list_head *os_tbl;	/* indexed by ID */
static struct list_head *os_pgrp_tbl;	/* indexed by PGRP */
static struct list_head *os_notify_tbl;	/* indexed by notify fd */
static LIST_HEAD(uid_cnt_list);
static int notify_epfd;			/* epoll used to monitor notify fds */
static pthread_t notify_poller_thread;
static pthread_t cuse_mixer_thread;
static pthread_t cuse_adsp_thread;
static pthread_cond_t notify_poller_kill_wait = PTHREAD_COND_INITIALIZER;

static void put_os(struct ossp_stream *os);


/***************************************************************************
 * Accessors
 */

static struct list_head *mixer_tbl_head(pid_t pid)
{
	return &mixer_tbl[pid % hashtbl_size];
}

static struct list_head *os_tbl_head(uint64_t id)
{
	return &os_tbl[id % hashtbl_size];
}

static struct list_head *os_pgrp_tbl_head(pid_t pgrp)
{
	return &os_pgrp_tbl[pgrp % hashtbl_size];
}

static struct list_head *os_notify_tbl_head(int notify_rx)
{
	return &os_notify_tbl[notify_rx % hashtbl_size];
}

static struct ossp_mixer *find_mixer_locked(pid_t pgrp)
{
	struct ossp_mixer *mixer;

	list_for_each_entry(mixer, mixer_tbl_head(pgrp), link)
		if (mixer->pgrp == pgrp)
			return mixer;
	return NULL;
}

static struct ossp_mixer *find_mixer(pid_t pgrp)
{
	struct ossp_mixer *mixer;

	pthread_mutex_lock(&mutex);
	mixer = find_mixer_locked(pgrp);
	pthread_mutex_unlock(&mutex);
	return mixer;
}

static struct ossp_stream *find_os(uint64_t id)
{
	struct ossp_stream *os, *found = NULL;

	pthread_mutex_lock(&mutex);
	list_for_each_entry(os, os_tbl_head(id), link)
		if (os->id == id) {
			found = os;
			break;
		}
	pthread_mutex_unlock(&mutex);
	return found;
}

static struct ossp_stream *find_os_by_notify_rx(int notify_rx)
{
	struct ossp_stream *os, *found = NULL;

	pthread_mutex_lock(&mutex);
	list_for_each_entry(os, os_notify_tbl_head(notify_rx), notify_link)
		if (os->notify_rx == notify_rx) {
			found = os;
			break;
		}
	pthread_mutex_unlock(&mutex);
	return found;
}


/***************************************************************************
 * Command and ioctl helpers
 */

static ssize_t exec_cmd(struct ossp_stream *os, enum ossp_opcode opcode,
	const void *carg, size_t carg_size, const void *din, size_t din_size,
	void *rarg, size_t rarg_size, void *dout, size_t *dout_sizep)
{
	size_t dout_size = dout_sizep ? *dout_sizep : 0;
	struct ossp_cmd cmd = { .magic = OSSP_CMD_MAGIC, .opcode = opcode,
				 .din_size = din_size,
				 .dout_size = dout_size };
	struct ossp_reply reply = { };
	char reason[512];
	int rc;

	if (os->dead)
		return -EIO;

	dbg1_os(os, "%s carg=%zu din=%zu rarg=%zu dout=%zu",
		ossp_cmd_str[opcode], carg_size, din_size, rarg_size,
		dout_size);

	pthread_mutex_lock(&os->cmd_mutex);

	if ((rc = write_fill(os->cmd_fd, &cmd, sizeof(cmd))) < 0 ||
	    (rc = write_fill(os->cmd_fd, carg, carg_size)) < 0 ||
	    (rc = write_fill(os->cmd_fd, din, din_size)) < 0) {
		snprintf(reason, sizeof(reason), "can't tranfer command: %s",
			 strerror(-rc));
		goto fail;
	}
	if ((rc = read_fill(os->reply_fd, &reply, sizeof(reply))) < 0) {
		snprintf(reason, sizeof(reason), "can't read reply: %s",
			 strerror(-rc));
		goto fail;
	}

	if (reply.magic != OSSP_REPLY_MAGIC) {
		snprintf(reason, sizeof(reason),
			 "reply magic mismatch %x != %x",
			 reply.magic, OSSP_REPLY_MAGIC);
		rc = -EINVAL;
		goto fail;
	}

	if (reply.result < 0)
		goto out_unlock;

	if (reply.dout_size > dout_size) {
		snprintf(reason, sizeof(reason),
			 "data out size overflow %zu > %zu",
			 reply.dout_size, dout_size);
		rc = -EINVAL;
		goto fail;
	}

	dout_size = reply.dout_size;
	if (dout_sizep)
		*dout_sizep = dout_size;

	if ((rc = read_fill(os->reply_fd, rarg, rarg_size)) < 0 ||
	    (rc = read_fill(os->reply_fd, dout, dout_size)) < 0) {
		snprintf(reason, sizeof(reason), "can't read data out: %s",
			 strerror(-rc));
		goto fail;
	}

 out_unlock:
	pthread_mutex_unlock(&os->cmd_mutex);
	dbg1_os(os, "  completed, result=%d dout=%zu",
		reply.result, dout_size);
	return reply.result;

 fail:
	pthread_mutex_unlock(&os->cmd_mutex);
	warn_os(os, "communication with slave failed (%s)", reason);
	os->dead = 1;
	return rc;
}

static ssize_t exec_simple_cmd(struct ossp_stream *os,
			       enum ossp_opcode opcode, void *carg, void *rarg)
{
	return exec_cmd(os, opcode,
			carg, ossp_arg_sizes[opcode].carg_size, NULL, 0,
			rarg, ossp_arg_sizes[opcode].rarg_size, NULL, NULL);
}

static int ioctl_prep_uarg(void *in, size_t in_sz, void *out, size_t out_sz,
			   void *uarg, const void *in_buf, size_t in_bufsz,
			   size_t *out_bufszp,
			   struct iovec *in_iov, struct iovec *out_iov)
{
	int retry = 0;

	if (in) {
		if (!in_bufsz) {
			in_iov[0].iov_base = uarg;
			in_iov[0].iov_len = in_sz;
			retry = 1;
		} else {
			assert(in_bufsz == in_sz);
			memcpy(in, in_buf, in_sz);
		}
	}

	if (out) {
		if (!*out_bufszp) {
			out_iov[0].iov_base = uarg;
			out_iov[0].iov_len = out_sz;
			retry = 1;
		} else {
			assert(*out_bufszp == out_sz);
			*out_bufszp = 0;
		}
	}

	return retry;
}

#define PREP_UARG(inp, outp) do {					\
	if (ioctl_prep_uarg(inp, sizeof(*inp), outp, sizeof(*outp),	\
			    uarg, in_buf, in_bufsz, out_bufszp,		\
			    in_iov, out_iov)) {				\
		*flagsp |= FUSE_IOCTL_RETRY;				\
		return 0;						\
	}								\
} while (0)

#define PUT_UARG(outp) do {						\
	memcpy(out_buf, outp, sizeof(*outp));				\
	*out_bufszp = sizeof(*outp);					\
} while (0)


/***************************************************************************
 * Mixer implementation
 */

static struct ossp_mixer *get_mixer(pid_t pgrp)
{
	struct ossp_mixer *mixer;

	pthread_mutex_lock(&mutex);

	mixer = find_mixer_locked(pgrp);
	if (mixer) {
		mixer->refcnt++;
		goto out_unlock;
	}

	mixer = calloc(1, sizeof(*mixer));
	if (!mixer) {
		warn("failed to allocate mixer for %d", pgrp);
		mixer = NULL;
		goto out_unlock;
	}

	mixer->pgrp = pgrp;
	INIT_LIST_HEAD(&mixer->link);
	mixer->refcnt = 1;
	memset(mixer->vol, -1, sizeof(mixer->vol));

	list_add(&mixer->link, mixer_tbl_head(pgrp));
	dbg0("CREATE mixer(%d)", pgrp);

 out_unlock:
	pthread_mutex_unlock(&mutex);
	return mixer;
}

static void put_mixer(struct ossp_mixer *mixer)
{
	if (!mixer)
		return;

	pthread_mutex_lock(&mutex);
	if (!--mixer->refcnt) {
		dbg0("DESTROY mixer(%d)", mixer->pgrp);
		list_del_init(&mixer->link);
		free(mixer);
	}
	pthread_mutex_unlock(&mutex);
}

static void init_mixer_cmd(struct ossp_mixer_cmd *mxcmd,
			   struct ossp_mixer *mixer)
{
	memset(mxcmd, 0, sizeof(*mxcmd));
	memset(&mxcmd->set.vol, -1, sizeof(mxcmd->set.vol));
	mxcmd->mixer = mixer;
	mxcmd->out_dir = -1;
}

static int exec_mixer_cmd(struct ossp_mixer_cmd *mxcmd, struct ossp_stream *os)
{
	struct ossp_mixer_arg arg = mxcmd->set;
	int i, j, rc;

	rc = exec_simple_cmd(os, OSSP_MIXER, &arg, &arg);
	if (rc >= 0) {
		for (i = 0; i < 2; i++)
			for (j = 0; j < 2; j++)
				mxcmd->get.vol[i][j] += arg.vol[i][j];
		mxcmd->nr_gets++;
		dbg1_os(os, "volume set=%d/%d:%d/%d get=%d/%d:%d/%d",
			mxcmd->set.vol[PLAY][LEFT], mxcmd->set.vol[PLAY][RIGHT],
			mxcmd->set.vol[REC][LEFT], mxcmd->set.vol[REC][RIGHT],
			mxcmd->get.vol[PLAY][LEFT], mxcmd->get.vol[PLAY][RIGHT],
			mxcmd->get.vol[REC][LEFT], mxcmd->get.vol[REC][RIGHT]);
	} else
		warn_ose(os, rc, "mixer command failed");
	return rc;
}

static void finish_mixer_cmd(struct ossp_mixer_cmd *mxcmd)
{
	struct ossp_mixer *mixer = mxcmd->mixer;
	int dir = mxcmd->out_dir;
	int nr_gets = mxcmd->nr_gets;
	int vol[2][2] = { { -1, -1 }, { -1, -1 } };
	int i, j, vol_changed = 0;

	pthread_mutex_lock(&mixer_mutex);

	for_each_vol(i, j) {
		if (mxcmd->set.vol[i][j] >= 0) {
			vol[i][j] = mxcmd->set.vol[i][j];
			vol_changed = 1;
		}
		if (nr_gets)
			vol[i][j] = mxcmd->get.vol[i][j] / nr_gets;
		else if (vol[i][j] < 0)
			vol[i][j] = 100;

		vol[i][j] = min(max(0, vol[i][j]), 100);
	}

	mixer->modify_counter += vol_changed;

	if (dir >= 0 && mxcmd->out_buf) {
		*(int *)mxcmd->out_buf = vol[dir][LEFT] |
					  (vol[dir][RIGHT] << 8);
		*mxcmd->out_bufszp = sizeof(int);
	}

	pthread_mutex_unlock(&mixer_mutex);
}

static int mixer_simple_ioctl(struct ossp_mixer *mixer, unsigned cmd,
			      void *uarg, unsigned *flagsp,
			      const void *in_buf, size_t in_bufsz,
			      void *out_buf, size_t *out_bufszp,
			      struct iovec *in_iov, struct iovec *out_iov)
{
	const char *id = "OSS Proxy", *name = "Mixer";
	int i;

	switch (cmd) {
	case SOUND_MIXER_INFO: {
		struct mixer_info info = { };

		PREP_UARG(NULL, &info);
		strncpy(info.id, id, sizeof(info.id) - 1);
		strncpy(info.name, name, sizeof(info.name) - 1);
		info.modify_counter = mixer->modify_counter;
		PUT_UARG(&info);
		return 0;
	}

	case SOUND_OLD_MIXER_INFO: {
		struct _old_mixer_info info = { };

		PREP_UARG(NULL, &info);
		strncpy(info.id, id, sizeof(info.id) - 1);
		strncpy(info.name, name, sizeof(info.name) - 1);
		PUT_UARG(&info);
		return 0;
	}

	case OSS_GETVERSION:
		i = SNDRV_OSS_VERSION;
		goto puti;
	case SOUND_MIXER_READ_DEVMASK:
	case SOUND_MIXER_READ_STEREODEVS:
		i = SOUND_MASK_PCM | SOUND_MASK_IGAIN;
		goto puti;
	case SOUND_MIXER_READ_CAPS:
		i = SOUND_CAP_EXCL_INPUT;
		goto puti;
	case SOUND_MIXER_READ_RECMASK:
	case SOUND_MIXER_READ_RECSRC:
		i = SOUND_MASK_IGAIN;
		goto puti;
	puti:
		PREP_UARG(NULL, &i);
		PUT_UARG(&i);
		return 0;

	case SOUND_MIXER_WRITE_RECSRC:
		return 0;
	}

	return -EAGAIN;
}

static int mixer_do_ioctl(struct ossp_mixer *mixer, unsigned cmd,
			  void *uarg, unsigned *flagsp,
			  const void *in_buf, size_t in_bufsz,
			  void *out_buf, size_t *out_bufszp,
			  struct iovec *in_iov, struct iovec *out_iov)
{
	int slot = cmd & 0xff, dir;
	struct ossp_mixer_cmd mxcmd;
	struct ossp_stream *os, **osa;
	int nr_os;
	int i, rc;

	rc = mixer_simple_ioctl(mixer, cmd, uarg, flagsp, in_buf, in_bufsz,
				out_buf, out_bufszp, in_iov, out_iov);
	if (rc != -EAGAIN)
		return rc;

	if (!(cmd & (SIOC_IN | SIOC_OUT)))
		return -ENXIO;

	/*
	 * Okay, it's not one of the easy ones.  Build mxcmd for
	 * actual volume control.
	 */
	if (cmd & SIOC_IN)
		PREP_UARG(&i, &i);
	else
		PREP_UARG(NULL, &i);

	switch (slot) {
	case SOUND_MIXER_PCM:
		dir = PLAY;
		break;
	case SOUND_MIXER_IGAIN:
		dir = REC;
		break;
	default:
		i = 0;
		PUT_UARG(&i);
		return 0;
	}

	init_mixer_cmd(&mxcmd, mixer);

	if (cmd & SIOC_IN) {
		unsigned l, r;

		l = i & 0xff;
		r = (i >> 8) & 0xff;
		if (l > 100 || r > 100)
			return -EINVAL;

		mixer->vol[dir][LEFT] = mxcmd.set.vol[dir][LEFT] = l;
		mixer->vol[dir][RIGHT] = mxcmd.set.vol[dir][RIGHT] = r;
	}
	mxcmd.out_dir = dir;
	mxcmd.out_buf = out_buf;
	mxcmd.out_bufszp = out_bufszp;

	/*
	 * Apply volume conrol
	 */
	/* acquire target streams */
	pthread_mutex_lock(&mutex);
	osa = calloc(max_streams, sizeof(osa[0]));
	if (!osa) {
		pthread_mutex_unlock(&mutex);
		return -ENOMEM;
	}

	nr_os = 0;
	list_for_each_entry(os, os_pgrp_tbl_head(mixer->pgrp), pgrp_link) {
		if (os->pgrp == mixer->pgrp) {
			osa[nr_os++] = os;
			os->refcnt++;
		}
 	}

	pthread_mutex_unlock(&mutex);

	/* execute mxcmd for each stream and put it */
	for (i = 0; i < nr_os; i++) {
		exec_mixer_cmd(&mxcmd, osa[i]);
		put_os(osa[i]);
	}

	finish_mixer_cmd(&mxcmd);
	free(osa);
	return 0;
}

static int mixer_open(const char *path, struct fuse_file_info *fi)
{
	pid_t pid = fuse_get_context()->pid, pgrp;
	struct ossp_mixer *mixer;
	int rc;

	rc = get_proc_self_info(pid, &pgrp, NULL, 0);
	if (rc) {
		err_e(rc, "get_proc_self_info(%d) failed", pid);
		return rc;
	}

	mixer = get_mixer(pgrp);
	fi->fh = pgrp;

	return mixer ? 0 : -ENOMEM;
}

static int mixer_ioctl(const char *path, int signed_cmd, void *uarg,
		       struct fuse_file_info *fi, unsigned *flagsp,
		       const void *in_buf, size_t in_bufsz,
		       void *out_buf, size_t *out_bufszp,
		       struct iovec *in_iov, struct iovec *out_iov)
{
	struct ossp_mixer *mixer;

	mixer = find_mixer(fi->fh);
	if (!mixer)
		return -EBADF;

	return mixer_do_ioctl(mixer, signed_cmd, uarg, flagsp, in_buf, in_bufsz,
			      out_buf, out_bufszp, in_iov, out_iov);
}

static int mixer_release(const char *path, struct fuse_file_info *fi)
{
	struct ossp_mixer *mixer;

	mixer = find_mixer(fi->fh);
	if (!mixer)
		return -EBADF;
	put_mixer(mixer);
	return 0;
}


/***************************************************************************
 * Stream implementation
 */

static int alloc_os(size_t stream_size, pid_t pid, uid_t pgrp,
		    uid_t uid, gid_t gid, int cmd_tx, int cmd_rx,
		    const int *notify, struct ossp_stream **osp)
{
	struct ossp_uid_cnt *tmp_ucnt, *ucnt = NULL;
	struct ossp_stream *os;
	int rc;

	assert(stream_size >= sizeof(struct ossp_stream));
	os = calloc(1, stream_size);
	if (!os)
		return -ENOMEM;

	INIT_LIST_HEAD(&os->link);
	INIT_LIST_HEAD(&os->pgrp_link);
	INIT_LIST_HEAD(&os->notify_link);
	os->refcnt = 1;

	rc = -pthread_mutex_init(&os->cmd_mutex, NULL);
	if (rc)
		goto err_free;

	pthread_mutex_lock(&mutex);

	rc = -EBUSY;
	if (nr_os + 1 > max_streams)
		goto err_unlock;

	list_for_each_entry(tmp_ucnt, &uid_cnt_list, link)
		if (tmp_ucnt->uid == uid) {
			ucnt = tmp_ucnt;
			break;
		}
	if (!ucnt) {
		rc = -ENOMEM;
		ucnt = calloc(1, sizeof(*ucnt));
		if (!ucnt)
			goto err_unlock;
		ucnt->uid = uid;
		list_add(&ucnt->link, &uid_cnt_list);
	}

	rc = -EBUSY;
	if (ucnt->nr_os + 1 > umax_streams)
		goto err_unlock;

	os->id = ++os_id;
	os->cmd_fd = cmd_tx;
	os->reply_fd = cmd_rx;
	os->notify_tx = notify[1];
	os->notify_rx = notify[0];
	os->pid = pid;
	os->pgrp = pgrp;
	os->uid = uid;
	os->gid = gid;
	os->ucnt = ucnt;

	list_add(&os->link, os_tbl_head(os->id));
	list_add(&os->pgrp_link, os_pgrp_tbl_head(os->pgrp));

	nr_os++;
	ucnt->nr_os++;
	*osp = os;
	pthread_mutex_unlock(&mutex);
	return 0;

 err_unlock:
	pthread_mutex_unlock(&mutex);
	pthread_mutex_destroy(&os->cmd_mutex);
 err_free:
	free(os);
	return rc;
}

static void shutdown_notification(struct ossp_stream *os)
{
	struct ossp_notify obituary = { .magic = OSSP_NOTIFY_MAGIC,
					.opcode = OSSP_NOTIFY_OBITUARY };
	ssize_t ret;

	/*
	 * Shutdown notification for this stream.  We politely ask
	 * notify_poller to shut the receive side down to avoid racing
	 * with it.
	 */
	while (os->notify_rx >= 0) {
		ret = write(os->notify_tx, &obituary, sizeof(obituary));
		if (ret <= 0) {
			if (ret == 0)
				warn_os(os, "unexpected EOF on notify_tx");
			else if (errno != EPIPE)
				warn_ose(os, -errno,
					 "unexpected error on notify_tx");
			close(os->notify_rx);
			os->notify_rx = -1;
			break;
		}

		if (ret != sizeof(obituary))
			warn_os(os, "short transfer on notify_tx");
		pthread_cond_wait(&notify_poller_kill_wait, &mutex);
	}
}

static void put_os(struct ossp_stream *os)
{
	if (!os)
		return;

	pthread_mutex_lock(&mutex);

	assert(os->refcnt);
	if (--os->refcnt) {
		pthread_mutex_unlock(&mutex);
		return;
	}

	os->dead = 1;
	shutdown_notification(os);

	dbg0_os(os, "DESTROY");

	list_del_init(&os->link);
	list_del_init(&os->pgrp_link);
	list_del_init(&os->notify_link);
	nr_os--;
	os->ucnt->nr_os--;

	pthread_mutex_unlock(&mutex);

	close(os->cmd_fd);
	close(os->reply_fd);
	close(os->notify_tx);
	put_mixer(os->mixer);
	free(os);
}

static int create_os(const char *slave_path, size_t stream_size,
		     pid_t pid, pid_t pgrp, uid_t uid, gid_t gid,
		     struct ossp_stream **osp)
{
	static pthread_mutex_t create_mutex = PTHREAD_MUTEX_INITIALIZER;
	int cmd_tx_pipe[2] = { -1, -1 };
	int cmd_rx_pipe[2] = { -1, -1 };
	int notify_pipe[2] = { -1, -1 };
	struct ossp_stream *os = NULL;
	struct epoll_event ev = { };
	int i, rc;

	/*
	 * Only one thread can be creating a stream.  This is to avoid
	 * leaking unwanted fds into slaves.
	 */
	pthread_mutex_lock(&create_mutex);

	/* prepare pipes */
	if (pipe(cmd_tx_pipe) || pipe(cmd_rx_pipe) || pipe(notify_pipe)) {
		rc = -errno;
		warn_ose(os, rc, "failed to create slave command pipe");
		goto close_all;
	}

	if (fcntl(notify_pipe[0], F_SETFL, O_NONBLOCK) < 0) {
		rc = -errno;
		warn_ose(os, rc, "failed to set NONBLOCK on notify pipe");
		goto close_all;
	}

	/*
	 * Alloc stream which will be responsible for all server side
	 * resources from now on.
	 */
	rc = alloc_os(stream_size, pid, pgrp, uid, gid,
		      cmd_tx_pipe[1], cmd_rx_pipe[0], notify_pipe, &os);
	if (rc) {
		warn_e(rc, "failed to allocate stream for %d", pid);
		goto close_all;
	}

	rc = -ENOMEM;
	os->mixer = get_mixer(pgrp);
	if (!os->mixer)
		goto put_os;

	/*
	 * Register notification.  If successful, notify_poller has
	 * custody of notify_rx fd.
	 */
	pthread_mutex_lock(&mutex);
	list_add(&os->notify_link, os_notify_tbl_head(os->notify_rx));
	pthread_mutex_unlock(&mutex);

	ev.events = EPOLLIN;
	ev.data.fd = notify_pipe[0];
	if (epoll_ctl(notify_epfd, EPOLL_CTL_ADD, notify_pipe[0], &ev)) {
		/*
		 * Without poller watching this notify pipe, poller
		 * shutdown sequence in shutdown_notification() can't
		 * be used.  Kill notification rx manually.
		 */
		rc = -errno;
		warn_ose(os, rc, "failed to add notify epoll");
		close(os->notify_rx);
		os->notify_rx = -1;
		goto put_os;
	}

	/* start slave */
	os->slave_pid = fork();
	if (os->slave_pid < 0) {
		rc = -errno;
		warn_ose(os, rc, "failed to fork slave");
		goto put_os;
	}

	if (os->slave_pid == 0) {
		/* child */
		char fd_str[3][16], log_str[16], slave_path_copy[PATH_MAX];
		char *argv[] = { slave_path_copy, "-c", fd_str[0],
				 "-r", fd_str[1], "-n", fd_str[2],
				 "-l", log_str, NULL, NULL };
		struct passwd *pwd;

		/* drop stuff we don't need */
		if (close(cmd_tx_pipe[1]) || close(cmd_rx_pipe[0]) ||
		    close(notify_pipe[0]))
			fatal_e(-errno, "failed to close server pipe fds");

		if (setresgid(os->gid, os->gid, os->gid) ||
		    setresuid(os->uid, os->uid, os->uid))
			fatal_e(-errno, "failed to drop privileges");

		clearenv();
		pwd = getpwuid(os->uid);
		if (pwd) {
			setenv("USER", pwd->pw_name,1);
			setenv("HOME", pwd->pw_dir,1);
		}

		/* prep and exec */
		slave_path_copy[sizeof(slave_path_copy) - 1] = '\0';
		strncpy(slave_path_copy, slave_path, sizeof(slave_path_copy) - 1);
		if (slave_path_copy[sizeof(slave_path_copy) - 1] != '\0') {
			rc = -errno;
			err_ose(os, rc, "slave path too long");
			goto child_fail;
		}

		snprintf(fd_str[0], sizeof(fd_str[0]), "%d", cmd_tx_pipe[0]);
		snprintf(fd_str[1], sizeof(fd_str[1]), "%d", cmd_rx_pipe[1]);
		snprintf(fd_str[2], sizeof(fd_str[2]), "%d", notify_pipe[1]);
		snprintf(log_str, sizeof(log_str), "%d", ossp_log_level);
		if (ossp_log_timestamp)
			argv[ARRAY_SIZE(argv) - 2] = "-t";

		execv(slave_path, argv);
		rc = -errno;
		err_ose(os, rc, "execv failed for <%d>", pid);
	child_fail:
		_exit(1);
	}

	/* turn on CLOEXEC on all server side fds */
	if (fcntl(os->cmd_fd, F_SETFD, FD_CLOEXEC) < 0 ||
	    fcntl(os->reply_fd, F_SETFD, FD_CLOEXEC) < 0 ||
	    fcntl(os->notify_tx, F_SETFD, FD_CLOEXEC) < 0 ||
	    fcntl(os->notify_rx, F_SETFD, FD_CLOEXEC) < 0) {
		rc = -errno;
		err_ose(os, rc, "failed to set CLOEXEC on server side fds");
		goto put_os;
	}

	dbg0_os(os, "CREATE slave=%d %s", os->slave_pid, slave_path);
	dbg0_os(os, "  client=%d cmd_tx=%d:%d cmd_rx=%d:%d notify=%d:%d",
		pid, cmd_tx_pipe[0], cmd_tx_pipe[1],
		cmd_rx_pipe[0], cmd_rx_pipe[1], notify_pipe[0], notify_pipe[1]);

	*osp = os;
	rc = 0;
	goto close_client_fds;

 put_os:
	put_os(os);
 close_client_fds:
	close(cmd_tx_pipe[0]);
	close(cmd_rx_pipe[1]);
	pthread_mutex_unlock(&create_mutex);
	return rc;

 close_all:
	for (i = 0; i < 2; i++) {
		close(cmd_tx_pipe[i]);
		close(cmd_rx_pipe[i]);
		close(notify_pipe[i]);
	}
	pthread_mutex_unlock(&create_mutex);
	return rc;
}

static int dsp_open(const char *path, struct fuse_file_info *fi)
{
	struct fuse_context *fuse_cxt = fuse_get_context();
	struct ossp_dsp_open_arg arg = { };
	struct ossp_stream *os = NULL;
	struct ossp_mixer *mixer;
	struct ossp_dsp_stream *dsps;
	struct ossp_mixer_cmd mxcmd;
	pid_t pgrp;
	ssize_t ret;

	ret = get_proc_self_info(fuse_cxt->pid, &pgrp, NULL, 0);
	if (ret) {
		err_e(ret, "get_proc_self_info(%d) failed", fuse_cxt->pid);
		return ret;
	}

	ret = create_os(dsp_slave_path, sizeof(*dsps), fuse_cxt->pid, pgrp,
			fuse_cxt->uid, fuse_cxt->gid, &os);
	if (ret)
		return ret;
	os->fuse = fuse_cxt->fuse;
	dsps = os_to_dsps(os);
	mixer = os->mixer;

	arg.flags = fi->flags;
	arg.opener_pid = os->pid;
	ret = exec_simple_cmd(&dsps->os, OSSP_DSP_OPEN, &arg, NULL);
	if (ret < 0) {
		put_os(os);
		return ret;
	}

	if (mixer->vol[PLAY][0] >= 0 || mixer->vol[REC][0] >= 0) {
		init_mixer_cmd(&mxcmd, mixer);
		memcpy(mxcmd.set.vol, mixer->vol, sizeof(mixer->vol));
		exec_mixer_cmd(&mxcmd, os);
		finish_mixer_cmd(&mxcmd);
	}

	fi->direct_io = 1;
	fi->nonseekable = 1;
	fi->fh = os->id;

	return 0;
}

static int dsp_release(const char *path, struct fuse_file_info *fi)
{
	struct ossp_stream *os;

	os = find_os(fi->fh);
	if (!os)
		return -EBADF;
	put_os(os);
	return 0;
}

static int dsp_read(const char *path, char *buf, size_t size, off_t off,
		    struct fuse_file_info *fi)
{
	struct ossp_dsp_rw_arg arg = { };
	struct ossp_stream *os;

	os = find_os(fi->fh);
	if (!os)
		return -EBADF;

	if (os_to_dsps(os)->nonblock_set)
		arg.nonblock = os_to_dsps(os)->nonblock;
	else
		arg.nonblock = fi->nonblock;

	return exec_cmd(os, OSSP_DSP_READ, &arg, sizeof(arg),
			NULL, 0, NULL, 0, buf, &size);
}

static int dsp_write(const char *path, const char *buf, size_t size, off_t off,
		     struct fuse_file_info *fi)
{
	struct ossp_dsp_rw_arg arg = { };
	struct ossp_stream *os;

	os = find_os(fi->fh);
	if (!os)
		return -EBADF;

	arg.nonblock = fi->nonblock || os_to_dsps(os)->nonblock;

	return exec_cmd(os, OSSP_DSP_WRITE, &arg, sizeof(arg),
			buf, size, NULL, 0, NULL, NULL);
}

static int dsp_poll(const char *path, struct fuse_file_info *fi,
		    unsigned int flags, unsigned *reventsp)
{
	int notify = !!(flags & FUSE_POLL_SCHEDULE_NOTIFY);
	struct ossp_stream *os;

	os = find_os(fi->fh);
	if (!os)
		return -EBADF;

	return exec_simple_cmd(os, OSSP_DSP_POLL, &notify, reventsp);
}

static int dsp_ioctl(const char *path, int signed_cmd, void *uarg,
		     struct fuse_file_info *fi, unsigned *flagsp,
		     const void *in_buf, size_t in_bufsz,
		     void *out_buf, size_t *out_bufszp,
		     struct iovec *in_iov, struct iovec *out_iov)
{
	/* some ioctl constants are long and has the highest bit set */
	unsigned cmd = signed_cmd;
	struct ossp_stream *os;
	struct ossp_dsp_stream *dsps;
	enum ossp_opcode op;
	ssize_t ret;
	int i;

	os = find_os(fi->fh);
	if (!os)
		return -EBADF;
	dsps = os_to_dsps(os);

	/* no compat yet */
	if (*flagsp & FUSE_IOCTL_COMPAT)
		return -ENOSYS;

	/* mixer commands are allowed on DSP devices */
	if (((cmd >> 8) & 0xff) == 'M')
		return mixer_do_ioctl(os->mixer, cmd, uarg, flagsp,
				      in_buf, in_bufsz, out_buf, out_bufszp,
				      in_iov, out_iov);

	/* and the rest */
	switch (cmd) {
	case OSS_GETVERSION:
		i = SNDRV_OSS_VERSION;
		PREP_UARG(NULL, &i);
		PUT_UARG(&i);
		return 0;

	case SNDCTL_DSP_GETCAPS:
		i = DSP_CAP_DUPLEX | DSP_CAP_REALTIME | DSP_CAP_TRIGGER |
			DSP_CAP_MULTI;
		PREP_UARG(NULL, &i);
		PUT_UARG(&i);
		return 0;

	case SNDCTL_DSP_NONBLOCK:
		dsps->nonblock = 1;
		return 0;

	case SNDCTL_DSP_RESET:		op = OSSP_DSP_RESET;		goto nd;
	case SNDCTL_DSP_SYNC:		op = OSSP_DSP_SYNC;		goto nd;
	case SNDCTL_DSP_POST:		op = OSSP_DSP_POST;		goto nd;
	nd:
		return exec_simple_cmd(&dsps->os, op, NULL, NULL);

	case SOUND_PCM_READ_RATE:	op = OSSP_DSP_GET_RATE;		goto ri;
	case SOUND_PCM_READ_BITS:	op = OSSP_DSP_GET_FORMAT;	goto ri;
	case SOUND_PCM_READ_CHANNELS:	op = OSSP_DSP_GET_CHANNELS;	goto ri;
	case SNDCTL_DSP_GETBLKSIZE:	op = OSSP_DSP_GET_BLKSIZE;	goto ri;
	case SNDCTL_DSP_GETFMTS:	op = OSSP_DSP_GET_FORMATS;	goto ri;
	case SNDCTL_DSP_GETTRIGGER:	op = OSSP_DSP_GET_TRIGGER;	goto ri;
	ri:
		PREP_UARG(NULL, &i);
		ret = exec_simple_cmd(&dsps->os, op, NULL, &i);
		if (ret == 0)
			PUT_UARG(&i);
		return ret;

	case SNDCTL_DSP_SPEED:		op = OSSP_DSP_SET_RATE;		goto wi;
	case SNDCTL_DSP_SETFMT:		op = OSSP_DSP_SET_FORMAT;	goto wi;
	case SNDCTL_DSP_CHANNELS:	op = OSSP_DSP_SET_CHANNELS;	goto wi;
	case SNDCTL_DSP_SUBDIVIDE:	op = OSSP_DSP_SET_SUBDIVISION;	goto wi;
	wi:
		PREP_UARG(&i, &i);
		ret = exec_simple_cmd(&dsps->os, op, &i, &i);
		if (ret == 0)
			PUT_UARG(&i);
		return ret;

	case SNDCTL_DSP_STEREO:
		PREP_UARG(NULL, &i);
		i = 2;
		ret = exec_simple_cmd(&dsps->os, OSSP_DSP_SET_CHANNELS, &i, &i);
		i--;
		if (ret == 0)
			PUT_UARG(&i);
		return ret;

	case SNDCTL_DSP_SETFRAGMENT:
		PREP_UARG(&i, NULL);
		return exec_simple_cmd(&dsps->os,
				       OSSP_DSP_SET_FRAGMENT, &i, NULL);

	case SNDCTL_DSP_SETTRIGGER:
		PREP_UARG(&i, NULL);
		return exec_simple_cmd(&dsps->os,
				       OSSP_DSP_SET_TRIGGER, &i, NULL);

	case SNDCTL_DSP_GETOSPACE:
	case SNDCTL_DSP_GETISPACE: {
		struct audio_buf_info info;

		op = cmd == SNDCTL_DSP_GETOSPACE ? OSSP_DSP_GET_OSPACE
						 : OSSP_DSP_GET_ISPACE;
		PREP_UARG(NULL, &info);
		ret = exec_simple_cmd(&dsps->os, op, NULL, &info);
		if (ret == 0)
			PUT_UARG(&info);
		return ret;
	}

	case SNDCTL_DSP_GETOPTR:
	case SNDCTL_DSP_GETIPTR: {
		struct count_info info;

		op = cmd == SNDCTL_DSP_GETOPTR ? OSSP_DSP_GET_OPTR
					       : OSSP_DSP_GET_IPTR;
		PREP_UARG(NULL, &info);
		ret = exec_simple_cmd(&dsps->os, op, NULL, &info);
		if (ret == 0)
			PUT_UARG(&info);
		return ret;
	}

	case SNDCTL_DSP_GETODELAY:
		PREP_UARG(NULL, &i);
		i = 0;
		ret = exec_simple_cmd(&dsps->os, OSSP_DSP_GET_ODELAY, NULL, &i);
		PUT_UARG(&i);	/* always put, 0 on failure */
		return ret;

	case SOUND_PCM_WRITE_FILTER:
	case SOUND_PCM_READ_FILTER:
		return -EIO;

	case SNDCTL_DSP_MAPINBUF:
	case SNDCTL_DSP_MAPOUTBUF:
		return -EINVAL;

	case SNDCTL_DSP_SETSYNCRO:
	case SNDCTL_DSP_SETDUPLEX:
	case SNDCTL_DSP_PROFILE:
		return 0;

	default:
		warn_os(os, "unknown ioctl 0x%x", cmd);
		return -EINVAL;
	}
}


/***************************************************************************
 * Notify poller
 */

static void *notify_poller(void *arg)
{
	struct epoll_event events[1024];
	int i, nfds;

 repeat:
	nfds = epoll_wait(notify_epfd, events, ARRAY_SIZE(events), -1);
	for (i = 0; i < nfds; i++) {
		int do_notify = 0;
		struct ossp_stream *os;
		struct ossp_notify notify;
		ssize_t ret;

		os = find_os_by_notify_rx(events[i].data.fd);
		if (!os) {
			err("can't find stream for notify_rx fd %d",
			    events[i].data.fd);
			epoll_ctl(notify_epfd, EPOLL_CTL_DEL, events[i].data.fd,
				  NULL);
			/* we don't know what's going on, don't close the fd */
			continue;
		}

		while ((ret = read(os->notify_rx,
				   &notify, sizeof(notify))) > 0) {
			if (os->dead)
				continue;
			if (ret != sizeof(notify)) {
				warn_os(os, "short read on notify_rx (%zu, "
					"expected %zu), killing the stream",
					ret, sizeof(notify));
				os->dead = 1;
				break;
			}
			if (notify.magic != OSSP_NOTIFY_MAGIC) {
				warn_os(os, "invalid magic on notification, "
					"killing the stream");
				os->dead = 1;
				break;
			}

			if (notify.opcode >= OSSP_NR_NOTIFY_OPCODES)
				goto unknown;

			dbg1_os(os, "NOTIFY %s", ossp_notify_str[notify.opcode]);

			switch (notify.opcode) {
			case OSSP_NOTIFY_POLL:
				do_notify = 1;
				break;
			case OSSP_NOTIFY_OBITUARY:
				os->dead = 1;
				break;
			case OSSP_NOTIFY_VOLCHG:
				pthread_mutex_lock(&mixer_mutex);
				os->mixer->modify_counter++;
				pthread_mutex_unlock(&mixer_mutex);
				break;
			default:
			unknown:
				warn_os(os, "unknown notification %d",
					notify.opcode);
			}
		}
		if (ret == 0)
			os->dead = 1;
		else if (ret < 0 && errno != EAGAIN) {
			warn_ose(os, -errno, "read fail on notify fd");
			os->dead = 1;
		}

		if (do_notify || os->dead)
			fuse_notify_poll(os->fuse, os->id);
		if (os->dead) {
			pthread_mutex_lock(&mutex);
			dbg0_os(os, "removing %d from notify poll list",
				os->notify_rx);
			epoll_ctl(notify_epfd, EPOLL_CTL_DEL, os->notify_rx,
				  NULL);
			close(os->notify_rx);
			os->notify_rx = -1;
			pthread_cond_broadcast(&notify_poller_kill_wait);
			pthread_mutex_unlock(&mutex);
		}
	}
	goto repeat;
}


/***************************************************************************
 * Stuff to bind and start everything
 */

static const struct cuse_operations mixer_ops = {
	.open		= mixer_open,
	.release	= mixer_release,
	.ioctl		= mixer_ioctl,
};

static const struct cuse_operations dsp_ops = {
	.open		= dsp_open,
	.release	= dsp_release,
	.read		= dsp_read,
	.write		= dsp_write,
	.poll		= dsp_poll,
	.ioctl		= dsp_ioctl,
};

static const char *usage =
"usage: osspd [options]\n"
"\n"
"options:\n"
"    --help            print this help message\n"
"    --dsp=NAME        DSP device name (default dsp)\n"
"    --dsp-maj=MAJ     DSP device major number (default 14)\n"
"    --dsp-min=MIN     DSP device minor number (default 3)\n"
"    --adsp=NAME       Aux DSP device name (default adsp, blank to disable)\n"
"    --adsp-maj=MAJ    Aux DSP device major number (default 14)\n"
"    --adsp-min=MIN    Aux DSP device minor number (default 12)\n"
"    --mixer=NAME      mixer device name (default mixer, blank to disable)\n"
"    --mixer-maj=MAJ   mixer device major number (default 14)\n"
"    --mixer-min=MIN   mixer device minor number (default 0)\n"
"    --max=MAX         maximum number of open streams (default 256)\n"
"    --umax=MAX        maximum number of open streams per UID (default --max)\n"
"    --dsp-slave=PATH  DSP slave (default ossp-padsp in the same dir)\n"
"    --log=LEVEL       log level (0..6)\n"
"    --timestamp       timestamp log messages\n"
"    -v                increase verbosity, can be specified multiple times\n"
"    -f                Run in foreground (don't daemonize)\n"
"\n";

struct ossp_param {
	char			*dsp_name;
	unsigned		dsp_major;
	unsigned		dsp_minor;
	char			*adsp_name;
	unsigned		adsp_major;
	unsigned		adsp_minor;
	char			*mixer_name;
	unsigned		mixer_major;
	unsigned		mixer_minor;
	unsigned		max_streams;
	unsigned		umax_streams;
	char			*dsp_slave_path;
	unsigned		log_level;
	int			timestamp;
	int			fg;
	int			help;
};

#define OSSP_OPT(t, p) { t, offsetof(struct ossp_param, p), 1 }

static const struct fuse_opt ossp_opts[] = {
	OSSP_OPT("--dsp=%s",		dsp_name),
	OSSP_OPT("--dsp-maj=%u",	dsp_major),
	OSSP_OPT("--dsp-min=%u",	dsp_minor),
	OSSP_OPT("--adsp=%s",		adsp_name),
	OSSP_OPT("--adsp-maj=%u",	adsp_major),
	OSSP_OPT("--adsp-min=%u",	adsp_minor),
	OSSP_OPT("--mixer=%s",		mixer_name),
	OSSP_OPT("--mixer-maj=%u",	mixer_major),
	OSSP_OPT("--mixer-min=%u",	mixer_minor),
	OSSP_OPT("--max=%u",		max_streams),
	OSSP_OPT("--umax=%u",		umax_streams),
	OSSP_OPT("--dsp-slave=%s",	dsp_slave_path),
	OSSP_OPT("--timestamp",		timestamp),
	OSSP_OPT("--log=%u",		log_level),
	OSSP_OPT("-f",			fg),
	FUSE_OPT_KEY("-h",		0),
	FUSE_OPT_KEY("--help",		0),
	FUSE_OPT_KEY("-v",		1),
	FUSE_OPT_END
};

struct ossp_cuse_data {
	char name_buf[128];
	struct cuse_operations ops;
	char *dinfo_argv[1];
	char *hinfo_argv[1];
};

static struct fuse *setup_ossp_cuse(const struct cuse_operations *base_ops,
				    const char *name, int major, int minor,
				    int argc, char **argv)
{
	struct ossp_cuse_data *data;
	struct fuse *fuse;
	int fd;

	data = calloc(1, sizeof(*data));
	snprintf(data->name_buf, sizeof(data->name_buf), "DEVNAME=%s", name);
	data->dinfo_argv[0] = data->name_buf;
	data->hinfo_argv[0] = "SUBSYSTEM=sound";

	data->ops = *base_ops;
	data->ops.dev_major = major;
	data->ops.dev_minor = minor;
	data->ops.dev_info_argc = ARRAY_SIZE(data->dinfo_argv);
	data->ops.dev_info_argv = (const char **)data->dinfo_argv;
	data->ops.hotplug_info_argc = ARRAY_SIZE(data->hinfo_argv);
	data->ops.hotplug_info_argv = (const char **)data->hinfo_argv;

	fuse = cuse_setup(argc, argv, &data->ops, NULL, NULL);
	if (!fuse) {
		err("failed to setup %s CUSE", name);
		return NULL;
	}

	fd = fuse_chan_fd(fuse_session_next_chan(fuse_get_session(fuse), NULL));
	if (fcntl(fd, F_SETFD, FD_CLOEXEC) < 0) {
		err_e(-errno, "failed to set CLOEXEC on %s CUSE fd", name);
		cuse_teardown(fuse);
		return NULL;
	}

	return fuse;
}

static void *cuse_worker(void *arg)
{
	struct fuse *fuse = arg;
	int rc;

	rc = fuse_loop_mt(fuse);
	cuse_teardown(fuse);

	return (void *)(unsigned long)rc;
}

static int process_arg(void *data, const char *arg, int key,
		       struct fuse_args *outargs)
{
	struct ossp_param *param = data;

	switch (key) {
	case 0:
		fprintf(stderr, usage);
		param->help = 1;
		return 0;
	case 1:
		param->log_level++;
		return 0;
	}
	return 1;
}

int main(int argc, char **argv)
{
	static struct ossp_param param = {
		.dsp_name = DFL_DSP_NAME,
		.dsp_major = DFL_DSP_MAJOR, .dsp_minor = DFL_DSP_MINOR,
		.adsp_name = DFL_ADSP_NAME,
		.adsp_major = DFL_ADSP_MAJOR, .adsp_minor = DFL_ADSP_MINOR,
		.mixer_name = DFL_MIXER_NAME,
		.mixer_major = DFL_MIXER_MAJOR, .mixer_minor = DFL_MIXER_MINOR,
		.max_streams = DFL_MAX_STREAMS,
	};
	struct fuse_args args = FUSE_ARGS_INIT(argc, argv);
	struct fuse *mixer_fuse = NULL, *dsp_fuse = NULL, *adsp_fuse = NULL;
	char path_buf[PATH_MAX], *dir;
	char adsp_buf[64] = "", mixer_buf[64] = "";
	struct sigaction sa;
	struct stat stat_buf;
	ssize_t ret;
	unsigned u;

	snprintf(ossp_log_name, sizeof(ossp_log_name), "osspd");
	param.log_level = ossp_log_level;

	if (fuse_opt_parse(&args, &param, ossp_opts, process_arg))
		fatal("failed to parse arguments");

	if (param.help)
		return 0;

	max_streams = param.max_streams;
	hashtbl_size = max_streams / 2 + 13;

	umax_streams = max_streams;
	if (param.umax_streams)
		umax_streams = param.umax_streams;
	if (param.log_level > OSSP_LOG_MAX)
		param.log_level = OSSP_LOG_MAX;
	if (!param.fg)
		param.log_level = -param.log_level;
	ossp_log_level = param.log_level;
	ossp_log_timestamp = param.timestamp;

	if (!param.fg && daemon(0, 0))
		fatal_e(-errno, "daemon() failed");

	/* daemonization already handled, prevent forking inside FUSE */
	fuse_opt_add_arg(&args, "-f");

	info("OSS Proxy v%s (C) 2008 by Tejun Heo <teheo@suse.de>",
	     OSSP_VERSION);

	/* we don't care about zombies and don't want stupid SIGPIPEs */
	memset(&sa, 0, sizeof(sa));
	sa.sa_handler = SIG_IGN;
	sa.sa_flags = SA_NOCLDSTOP | SA_NOCLDWAIT;
	if (sigaction(SIGCHLD, &sa, NULL))
		fatal_e(-errno, "failed to ignore SIGCHLD");

	memset(&sa, 0, sizeof(sa));
	sa.sa_handler = SIG_IGN;
	if (sigaction(SIGPIPE, &sa, NULL))
		fatal_e(-errno, "failed to ignore SIGPIPE");

	/* determine slave path and check for availability */
	ret = readlink("/proc/self/exe", path_buf, PATH_MAX - 1);
	if (ret < 0)
		fatal_e(-errno, "failed to determine executable path");
	path_buf[ret] = '\0';
	dir = dirname(path_buf);

	if (param.dsp_slave_path) {
		strncpy(dsp_slave_path, param.dsp_slave_path, PATH_MAX - 1);
		dsp_slave_path[PATH_MAX - 1] = '\0';
	} else {
		ret = snprintf(dsp_slave_path, PATH_MAX, "%s/%s",
			       dir, "ossp-padsp");
		if (ret >= PATH_MAX)
			fatal("dsp slave pathname too long");
	}

	if (stat(dsp_slave_path, &stat_buf))
		fatal_e(-errno, "failed to stat %s", dsp_slave_path);
	if (!S_ISREG(stat_buf.st_mode) || !(stat_buf.st_mode & 0444))
		fatal("%s is not executable", dsp_slave_path);

	/* allocate tables */
	mixer_tbl = calloc(hashtbl_size, sizeof(mixer_tbl[0]));
	os_tbl = calloc(hashtbl_size, sizeof(os_tbl[0]));
	os_pgrp_tbl = calloc(hashtbl_size, sizeof(os_pgrp_tbl[0]));
	os_notify_tbl = calloc(hashtbl_size, sizeof(os_notify_tbl[0]));
	if (!mixer_tbl || !os_tbl || !os_pgrp_tbl || !os_notify_tbl)
		fatal("failed to allocate stream hash tables");
	for (u = 0; u < hashtbl_size; u++) {
		INIT_LIST_HEAD(&mixer_tbl[u]);
		INIT_LIST_HEAD(&os_tbl[u]);
		INIT_LIST_HEAD(&os_pgrp_tbl[u]);
		INIT_LIST_HEAD(&os_notify_tbl[u]);
	}

	/* create notify epoll and kick off watcher thread */
	notify_epfd = epoll_create(max_streams);
	if (notify_epfd < 0)
		fatal_e(-errno, "failed to create notify epoll");
	if (fcntl(notify_epfd, F_SETFD, FD_CLOEXEC) < 0)
		fatal_e(-errno, "failed to set CLOEXEC on notify epfd");

	ret = -pthread_create(&notify_poller_thread, NULL, notify_poller, NULL);
	if (ret)
		fatal_e(ret, "failed to create notify poller thread");

	/* we're set, let's setup fuse structures */
	if (strlen(param.mixer_name))
		mixer_fuse = setup_ossp_cuse(&mixer_ops, param.mixer_name,
					     param.mixer_major, param.mixer_minor,
					     args.argc, args.argv);
	if (strlen(param.adsp_name))
		adsp_fuse = setup_ossp_cuse(&dsp_ops, param.adsp_name,
					    param.adsp_major, param.adsp_minor,
					    args.argc, args.argv);

	dsp_fuse = setup_ossp_cuse(&dsp_ops, param.dsp_name,
				   param.dsp_major, param.dsp_minor,
				   args.argc, args.argv);
	if (!dsp_fuse)
		fatal("can't create dsp, giving up");

	if (mixer_fuse)
		snprintf(mixer_buf, sizeof(mixer_buf), ", %s (%d:%d)",
			 param.mixer_name, param.mixer_major, param.mixer_minor);
	if (adsp_fuse)
		snprintf(adsp_buf, sizeof(adsp_buf), ", %s (%d:%d)",
			 param.adsp_name, param.adsp_major, param.adsp_minor);

	info("Creating %s (%d:%d)%s%s", param.dsp_name, param.dsp_major,
	     param.dsp_minor, adsp_buf, mixer_buf);

	/* start threads for mixer and adsp */
	if (mixer_fuse) {
		ret = -pthread_create(&cuse_mixer_thread, NULL,
				      cuse_worker, mixer_fuse);
		if (ret)
			err_e(ret, "failed to create mixer worker");
	}
	if (adsp_fuse) {
		ret = -pthread_create(&cuse_adsp_thread, NULL,
				      cuse_worker, adsp_fuse);
		if (ret)
			err_e(ret, "failed to create adsp worker");
	}

	/* run CUSE for /dev/dsp in the main thread */
	ret = (ssize_t)cuse_worker(dsp_fuse);
	if (ret < 0)
		fatal("dsp worker failed");
	return 0;
}
