/*
 * ossp-util - OSS Proxy: Common utilities
 *
 * Copyright (C) 2008-2009  SUSE Linux Products GmbH
 * Copyright (C) 2008-2009  Tejun Heo <tj@kernel.org>
 *
 * This file is released under the GPLv2.
 */

#include <ctype.h>
#include <fcntl.h>
#include <inttypes.h>
#include <limits.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/uio.h>
#include <syslog.h>
#include <unistd.h>
#include "ossp-util.h"

char ossp_log_name[OSSP_LOG_NAME_LEN];
int ossp_log_level = OSSP_LOG_DFL;
int ossp_log_timestamp;

static const char *severity_strs[] = {
	[OSSP_LOG_CRIT]		= "CRIT",
	[OSSP_LOG_ERR]		= " ERR",
	[OSSP_LOG_WARN]		= "WARN",
	[OSSP_LOG_INFO]		= NULL,
	[OSSP_LOG_DBG0]		= "DBG0",
	[OSSP_LOG_DBG1]		= "DBG1",
};

static int severity_map[] = {
	[OSSP_LOG_CRIT]		= LOG_ERR,
	[OSSP_LOG_ERR]		= LOG_ERR,
	[OSSP_LOG_WARN]		= LOG_WARNING,
	[OSSP_LOG_INFO]		= LOG_INFO,
	[OSSP_LOG_DBG0]		= LOG_DEBUG,
	[OSSP_LOG_DBG1]		= LOG_DEBUG,
};

void log_msg(int severity, const char *fmt, ...)
{
	static int syslog_opened = 0;
	char buf[1024];
	size_t len = sizeof(buf), off = 0;
	va_list ap;

	if (severity > abs(ossp_log_level))
		return;

	if (ossp_log_level < 0 && !syslog_opened)
		openlog(ossp_log_name, 0, LOG_DAEMON);

	assert(severity >= 0 && severity < ARRAY_SIZE(severity_strs));

	if (ossp_log_timestamp) {
		static uint64_t start;
		uint64_t now;
		struct timeval tv;
		gettimeofday(&tv, NULL);
		now = tv.tv_sec * 1000 + tv.tv_usec / 1000;
		if (!start)
			start = now;

		off += snprintf(buf + off, len - off, "<%08"PRIu64"> ",
				now - start);
	}

	if (ossp_log_level > 0) {
		char sev_buf[16] = "";
		if (severity_strs[severity])
			snprintf(sev_buf, sizeof(sev_buf), " %s",
				 severity_strs[severity]);
		off += snprintf(buf + off, len - off, "%s%s: ",
				ossp_log_name, sev_buf);
	} else if (severity_strs[severity])
		off += snprintf(buf + off, len - off, "%s ",
				severity_strs[severity]);

	va_start(ap, fmt);
	off += vsnprintf(buf + off, len - off, fmt, ap);
	va_end(ap);

	off += snprintf(buf + off, len - off, "\n");

	if (ossp_log_level > 0)
		fputs(buf, stderr);
	else
		syslog(severity_map[severity], "%s", buf);
}

int read_fill(int fd, void *buf, size_t size)
{
	while (size) {
		ssize_t ret;
		int rc;

		ret = read(fd, buf, size);
		if (ret <= 0) {
			if (ret == 0)
				rc = -EIO;
			else
				rc = -errno;
			err_e(rc, "failed to read_fill %zu bytes from fd %d",
			      size, fd);
			return rc;
		}
		buf += ret;
		size -= ret;
	}
	return 0;
}

int write_fill(int fd, const void *buf, size_t size)
{
	while (size) {
		ssize_t ret;
		int rc;

		ret = write(fd, buf, size);
		if (ret <= 0) {
			if (ret == 0)
				rc = -EIO;
			else
				rc = -errno;
			err_e(rc, "failed to write_fill %zu bytes to fd %d",
			      size, fd);
			return rc;
		}
		buf += ret;
		size -= ret;
	}
	return 0;
}

void ring_fill(struct ring_buf *ring, const void *buf, size_t size)
{
	size_t tail;

	assert(ring_space(ring) >= size);

	tail = (ring->head + ring->size - ring->bytes) % ring->size;

	if (ring->head >= tail) {
		size_t todo = min(size, ring->size - ring->head);

		memcpy(ring->buf + ring->head, buf, todo);
		ring->head = (ring->head + todo) % ring->size;
		ring->bytes += todo;
		buf += todo;
		size -= todo;
	}

	assert(ring->size - ring->head >= size);
	memcpy(ring->buf + ring->head, buf, size);
	ring->head += size;
	ring->bytes += size;
}

void *ring_data(struct ring_buf *ring, size_t *sizep)
{
	size_t tail;

	if (!ring->bytes)
		return NULL;

	tail = (ring->head + ring->size - ring->bytes) % ring->size;

	*sizep = min(ring->bytes, ring->size - tail);
	return ring->buf + tail;
}

int ring_resize(struct ring_buf *ring, size_t new_size)
{
	struct ring_buf new_ring = { .size = new_size };
	void *p;
	size_t size;

	if (ring_bytes(ring) > new_size)
		return -ENOSPC;

	new_ring.buf = calloc(1, new_size);
	if (new_size && !new_ring.buf)
		return -ENOMEM;

	while ((p = ring_data(ring, &size))) {
		ring_fill(&new_ring, p, size);
		ring_consume(ring, size);
	}

	free(ring->buf);
	*ring = new_ring;
	return 0;
}

int ensure_sbuf_size(struct sized_buf *sbuf, size_t size)
{
	char *new_buf;

	if (sbuf->size >= size)
		return 0;

	new_buf = realloc(sbuf->buf, size);
	if (size && !new_buf)
		return -ENOMEM;

	sbuf->buf = new_buf;
	sbuf->size = size;
	return 0;
}

int get_proc_self_info(pid_t pid, pid_t *ppid_r,
		       char *cmd_buf, size_t cmd_buf_sz)

{
	char path[64], buf[4096];
	int fd = -1;
	char *cmd_start, *cmd_end, *ppid_start, *end;
	ssize_t ret;
	pid_t ppid;
	int i, rc;

	snprintf(path, sizeof(path), "/proc/%ld/stat", (long)pid);
	fd = open(path, O_RDONLY);
	if (fd < 0) {
		rc = -errno;
		goto out;
	}

	ret = read(fd, buf, sizeof(buf));
	if (ret < 0)
		goto out;
	if (ret == sizeof(buf)) {
		rc = -EOVERFLOW;
		goto out;
	}
	buf[ret] = '\0';

	rc = -EINVAL;
	cmd_start = strchr(buf, '(');
	cmd_end = strrchr(buf, ')');
	if (!cmd_start || !cmd_end)
		goto out;
	cmd_start++;

	ppid_start = cmd_end;
	for (i = 0; i < 3; i++) {
		ppid_start = strchr(ppid_start, ' ');
		if (!ppid_start)
			goto out;
		ppid_start++;
	}

	ppid = strtoul(ppid_start, &end, 10);
	if (end == ppid_start || *end != ' ')
		goto out;

	if (ppid_r)
		*ppid_r = ppid;
	if (cmd_buf) {
		size_t len = min_t(size_t, cmd_end - cmd_start, cmd_buf_sz - 1);
		memcpy(cmd_buf, cmd_start, len);
		cmd_buf[len] = '\0';
	}

	rc = 0;
 out:
	close(fd);

	return rc;
}

int ossp_slave_process_command(int cmd_fd,
			       ossp_action_fn_t const *action_fn_tbl,
			       int (*action_pre_fn)(void),
			       void (*action_post_fn)(void))
{
	static struct sized_buf carg_sbuf = { }, rarg_sbuf = { };
	static struct sized_buf din_sbuf = { }, dout_sbuf = { };
	struct ossp_cmd cmd;
	int fd = -1;
	char cmsg_buf[CMSG_SPACE(sizeof(fd))];
	struct iovec iov = { &cmd, sizeof(cmd) };
	struct msghdr msg = { .msg_iov = &iov, .msg_iovlen = 1,
			      .msg_control = cmsg_buf,
			      .msg_controllen = sizeof(cmsg_buf) };
	struct cmsghdr *cmsg;
	size_t carg_size, din_size, rarg_size, dout_size;
	char *carg = NULL, *din = NULL, *rarg = NULL, *dout = NULL;
	struct ossp_reply reply = { .magic = OSSP_REPLY_MAGIC };
	ssize_t ret;

	ret = recvmsg(cmd_fd, &msg, 0);
	if (ret == 0)
		return 0;
	if (ret < 0) {
		ret = -errno;
		err_e(ret, "failed to read command channel");
		return ret;
	}

	if (ret != sizeof(cmd)) {
		err("command struct size mismatch (%zu, should be %zu)",
		    ret, sizeof(cmd));
		return -EINVAL;
	}

	if (cmd.magic != OSSP_CMD_MAGIC) {
		err("illegal command magic 0x%x", cmd.magic);
		return -EINVAL;
	}

	for (cmsg = CMSG_FIRSTHDR(&msg); cmsg;
	     cmsg = CMSG_NXTHDR(&msg, cmsg)) {
		if (cmsg->cmsg_level == SOL_SOCKET &&
		    cmsg->cmsg_type == SCM_RIGHTS)
			fd = *(int *)CMSG_DATA(cmsg);
		else {
			err("unknown cmsg %d:%d received (opcode %d)",
			    cmsg->cmsg_level, cmsg->cmsg_type, cmd.opcode);
			return -EINVAL;
		}
	}

	if (cmd.opcode >= OSSP_NR_OPCODES) {
		err("unknown opcode %d", cmd.opcode);
		return -EINVAL;
	}

	carg_size = ossp_arg_sizes[cmd.opcode].carg_size;
	din_size = cmd.din_size;
	rarg_size = ossp_arg_sizes[cmd.opcode].rarg_size;
	dout_size = cmd.dout_size;

	if ((fd >= 0) != ossp_arg_sizes[cmd.opcode].has_fd) {
		err("fd=%d unexpected for opcode %d", fd, cmd.opcode);
		return -EINVAL;
	}

	if (ensure_sbuf_size(&carg_sbuf, carg_size) ||
	    ensure_sbuf_size(&din_sbuf, din_size) ||
	    ensure_sbuf_size(&rarg_sbuf, rarg_size) ||
	    ensure_sbuf_size(&dout_sbuf, dout_size)) {
		err("failed to allocate command buffers");
		return -ENOMEM;
	}

	if (carg_size) {
		carg = carg_sbuf.buf;
		ret = read_fill(cmd_fd, carg, carg_size);
		if (ret < 0)
			return ret;
	}
	if (din_size) {
		din = din_sbuf.buf;
		ret = read_fill(cmd_fd, din, din_size);
		if (ret < 0)
			return ret;
	}
	if (rarg_size)
		rarg = rarg_sbuf.buf;
	if (dout_size)
		dout = dout_sbuf.buf;

	ret = -EINVAL;
	if (action_fn_tbl[cmd.opcode]) {
		ret = action_pre_fn();
		if (ret == 0) {
			ret = action_fn_tbl[cmd.opcode](cmd.opcode, carg,
							din, din_size, rarg,
							dout, &dout_size, fd);
			action_post_fn();
		}
	}

	reply.result = ret;
	if (ret >= 0)
		reply.dout_size = dout_size;
	else {
		rarg_size = 0;
		dout_size = 0;
	}

	if (write_fill(cmd_fd, &reply, sizeof(reply)) < 0 ||
	    write_fill(cmd_fd, rarg, rarg_size) < 0 ||
	    write_fill(cmd_fd, dout, dout_size) < 0)
		return -EIO;

	return 1;
}
