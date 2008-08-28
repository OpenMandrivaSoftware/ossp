/*
 * ossp-padsp - ossp DSP slave which forwards to pulseaduio
 *
 * Copyright (C) 2008       SUSE Linux Products GmbH
 * Copyright (C) 2008       Tejun Heo <teheo@suse.de>
 *
 * This file is released under the GPLv2.
 */

#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <getopt.h>
#include <libgen.h>
#include <limits.h>
#include <poll.h>
#include <pthread.h>
#include <pwd.h>
#include <signal.h>
#include <stdarg.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include <pulse/pulseaudio.h>
#include <sys/soundcard.h>

#include "ossp.h"
#include "ossp-util.h"

#define AFMT_FLOAT       0x00004000
#define AFMT_S32_LE      0x00001000
#define AFMT_S32_BE      0x00002000

static int cmd_fd = -1, reply_fd = -1, notify_fd = -1;
static pa_context *context;
static pa_threaded_mainloop *mainloop;
static pa_mainloop_api *mainloop_api;
static char username[128];
static char stream_name[128];
static int stream_enabled[2];
static int stream_corked[2];
static int stream_waiting;
static int stream_notify;
static pa_channel_map channel_map_stor;
static pa_channel_map *channel_map;
static pa_stream *stream[2];
static pa_usec_t stream_ptr_timestamp[2];
static struct sized_buf rec_sbuf;
static size_t rec_buf_sz;
static int stored_oss_vol[2][2] = { { -1, -1 }, { -1, -1 } };
static int fail_code;

static pa_sample_spec sample_spec = {
	.format = PA_SAMPLE_U8,
	.rate = 8000,
	.channels = 1,
};
static int fragshift;		/* number of bytes in a fragment in shifts */
static int subdivision;		/* alternative way to determine fragsize */
static int fragsize;		/* calculated fragment size in bytes */
static int maxfrags;		/* maximum number of fragments */

static const char *dir_str[] = {
	[PLAY]		= "playback",
	[REC]		= "recording",
};

static const char *usage =
"usage: ossp-padsp -c CMD_FD -r REPLY_FD -n NOTIFY_FD [-d]\n"
"\n"
"proxies commands from osspd to pulseaudio\n"
"\n"
"options:\n"
"    -c CMD_FD         fd to receive commands from osspd\n"
"    -r REPLY_FD       fd to send replies to commands\n"
"    -n NOTIFY_FD      fd to send async notifications to osspd\n"
"    -l LOG_LEVEL      set log level\n"
"    -t                enable log timestamps\n";

static void stream_rw_callback(pa_stream *s, size_t length, void *userdata);

#define __pa_err		pa_strerror(pa_context_errno(context))
#define dbg1_pa(fmt, args...)	dbg1(fmt" (%s)" , ##args, __pa_err)
#define dbg0_pa(fmt, args...)	dbg0(fmt" (%s)" , ##args, __pa_err)
#define info_pa(fmt, args...)	info(fmt" (%s)" , ##args, __pa_err)
#define warn_pa(fmt, args...)	warn(fmt" (%s)" , ##args, __pa_err)
#define err_pa(fmt, args...)	err(fmt" (%s)" , ##args, __pa_err)

static int do_mixer(int dir, int *vol);

static int padsp_done(void)
{
	fail_code = -EIO;
	mainloop_api->quit(mainloop_api, 1);
	return fail_code;
}

static int fmt_oss_to_pa(int fmt)
{
	switch (fmt) {
	case AFMT_U8:			return PA_SAMPLE_U8;
	case AFMT_A_LAW:		return PA_SAMPLE_ALAW;
	case AFMT_MU_LAW:		return PA_SAMPLE_ULAW;
	case AFMT_S16_LE:		return PA_SAMPLE_S16LE;
	case AFMT_S16_BE:		return PA_SAMPLE_S16BE;
	case AFMT_FLOAT:		return PA_SAMPLE_FLOAT32NE;
	case AFMT_S32_LE:		return PA_SAMPLE_S32LE;
	case AFMT_S32_BE:		return PA_SAMPLE_S32BE;
	default:			return PA_SAMPLE_U8;
	}
}

static int fmt_pa_to_oss(int fmt)
{
	switch (fmt) {
	case PA_SAMPLE_U8:		return AFMT_U8;
	case PA_SAMPLE_ALAW:		return AFMT_A_LAW;
	case PA_SAMPLE_ULAW:		return AFMT_MU_LAW;
	case PA_SAMPLE_S16LE:		return AFMT_S16_LE;
	case PA_SAMPLE_S16BE:		return AFMT_S16_BE;
	case PA_SAMPLE_FLOAT32NE:	return AFMT_FLOAT;
	case PA_SAMPLE_S32LE:		return AFMT_S32_LE;
	case PA_SAMPLE_S32BE:		return AFMT_S32_BE;
	default:			return AFMT_U8;
	}
}

#define EXEC_OP(op, args...)	do {					\
	pa_operation *_o;						\
	_o = op(args);							\
	if (_o) {							\
		while (pa_operation_get_state(_o) != PA_OPERATION_DONE)	\
			pa_threaded_mainloop_wait(mainloop);		\
		pa_operation_unref(_o);					\
	} } while (0)

static void context_op_callback(pa_context *s, int success, void *userdata)
{
	*(int *)userdata = success;
	pa_threaded_mainloop_signal(mainloop, 0);
}

static void stream_op_callback(pa_stream *s, int success, void *userdata)
{
	*(int *)userdata = success;
	pa_threaded_mainloop_signal(mainloop, 0);
}

#define EXEC_CONTEXT_OP(op, args...) ({					\
	int _success;							\
	EXEC_OP(op , ##args, context_op_callback, &_success);		\
	if (!_success)							\
		warn_pa("%s() failed", #op);				\
	_success ? 0 : -EIO; })

#define EXEC_STREAM_OP(op, args...) ({					\
	int _success;							\
	EXEC_OP(op , ##args, stream_op_callback, &_success);		\
	if (!_success)							\
		warn_pa("%s() failed", #op);				\
	_success ? 0 : -EIO; })

static void flush_streams(int drain)
{
	int i;

	if (!(stream[PLAY] || stream[REC]))
		return;

	dbg0("FLUSH drain=%d", drain);

	if (drain && stream[PLAY])
		EXEC_STREAM_OP(pa_stream_drain, stream[PLAY]);

	for (i = 0; i < 2; i++)
		if (stream[i])
			EXEC_STREAM_OP(pa_stream_flush, stream[i]);

	rec_buf_sz = 0;
}

static void kill_streams(void)
{
	int i;

	if (!(stream[PLAY] || stream[REC]))
		return;

	flush_streams(1);

	dbg0("KILL");

	for (i = 0; i < 2; i++) {
		if (!stream[i])
			continue;
		pa_stream_disconnect(stream[i]);
		pa_stream_unref(stream[i]);
		stream[i] = NULL;
		stream_ptr_timestamp[i] = 0;
	}
}

static void stream_state_callback(pa_stream *s, void *userdata)
{
	pa_threaded_mainloop_signal(mainloop, 0);
}

static int prepare_streams(void)
{
	int dir;

	for (dir = 0; dir < 2; dir++) {
		char buf[128];
		pa_stream *s;
		size_t bps;
		pa_stream_flags_t flags;
		const pa_buffer_attr *ba;
		pa_buffer_attr new_ba;
		int vol[2];

		if (!stream_enabled[dir] || stream[dir])
			continue;

		dbg0("CREATE %s %s fsft=%d subd=%d maxf=%d", dir_str[dir],
		     pa_sample_spec_snprint(buf, sizeof(buf), &sample_spec),
		     fragshift, subdivision, maxfrags);

		channel_map = pa_channel_map_init_auto(&channel_map_stor,
						       sample_spec.channels,
						       PA_CHANNEL_MAP_OSS);

		s = pa_stream_new(context, stream_name, &sample_spec,
				  channel_map);
		if (!s) {
			err_pa("can't create streams");
			goto fail;
		}
		stream[dir] = s;

		pa_stream_set_state_callback(s, stream_state_callback, NULL);
		pa_stream_set_write_callback(s, stream_rw_callback, NULL);
		pa_stream_set_read_callback(s, stream_rw_callback, NULL);

		flags = PA_STREAM_AUTO_TIMING_UPDATE |
			PA_STREAM_INTERPOLATE_TIMING;
		if (stream_corked[dir])
			flags |= PA_STREAM_START_CORKED;

		if (dir == PLAY) {
			if (pa_stream_connect_playback(s, NULL, NULL, flags,
						       NULL, NULL)) {
				err_pa("failed to connect playback stream");
				goto fail;
			}
		} else {
			if (pa_stream_connect_record(s, NULL, NULL, flags)) {
				err_pa("failed to connect record stream");
				goto fail;
			}
		}

		while (pa_stream_get_state(s) == PA_STREAM_CREATING)
			pa_threaded_mainloop_wait(mainloop);
		if (pa_stream_get_state(s) != PA_STREAM_READY) {
			err_pa("failed to connect stream (state=%d)",
			       pa_stream_get_state(s));
			goto fail;
		}

		/* Calculate and set buffer attributes.  OSS
		 * applications assume shorter default latency than
		 * the PA default.  Default to ~250ms used by
		 * snd_pcm_oss.
		 */
		ba = pa_stream_get_buffer_attr(s);
		if (!ba) {
			err_pa("failed to get buffer attributes");
			goto fail;
		}
		new_ba = *ba;

		bps = pa_bytes_per_second(&sample_spec);

		if (fragshift) {
			/* user requested specific size, honor it */
			fragsize = 1 << fragshift;
			if (fragsize > ba->maxlength / 2)
				fragsize = ba->maxlength / 2;
		} else {
			int sd = subdivision ?: 4;
			size_t target = bps / sd;

			/* calculate the first log2 below target */
			fragsize = ba->maxlength;
			do {
				fragsize /= 2;
			} while (fragsize > target);

			if (fragsize < 16)
				fragsize = 16;
		}

		if (maxfrags && fragsize * maxfrags < new_ba.maxlength)
			new_ba.maxlength = fragsize * maxfrags;
		maxfrags = new_ba.maxlength / fragsize;

		new_ba.tlength = new_ba.maxlength;
		new_ba.prebuf = 2 * fragsize;
		new_ba.minreq = fragsize;
		new_ba.fragsize = fragsize;

		/* apply calculated buffer attributes */
		EXEC_STREAM_OP(pa_stream_set_buffer_attr, s, &new_ba);

		ba = pa_stream_get_buffer_attr(s);
		if (!ba) {
			err_pa("failed to get buffer attributes");
			goto fail;
		}

		dbg0("  max=%u:%zu tlen=%u:%zu pre=%u:%zu",
		     ba->maxlength, ba->maxlength * 1000 / bps,
		     ba->tlength, ba->tlength * 1000 / bps,
		     ba->prebuf, ba->prebuf * 1000 / bps);
		dbg0("  req=%u:%zu rec=%u:%zu",
		     ba->minreq, ba->minreq * 1000 / bps,
		     ba->fragsize, ba->fragsize * 1000 / bps);
		dbg0("  subd=%d fsz=%d:%zu maxf=%d",
		     subdivision, fragsize, fragsize * 1000 / bps, maxfrags);

		/* apply stored OSS volume */
		memcpy(vol, stored_oss_vol[dir], sizeof(vol));
		if (do_mixer(dir, vol))
			warn_pa("initial volume control failed");
	}
	return 0;
 fail:
	return padsp_done();
}

struct volume_ret {
	int			success;
	pa_cvolume		*cv;
};

static void play_volume_callback(pa_context *c, const pa_sink_input_info *i,
				 int eol, void *userdata)
{
	struct volume_ret *vr = userdata;

	if (i) {
		*vr->cv = i->volume;
		vr->success = 1;
	}
	pa_threaded_mainloop_signal(mainloop, 0);
}

static void rec_volume_callback(pa_context *c, const pa_source_info *i,
				int eol, void *userdata)
{
	struct volume_ret *vr = userdata;

	if (i) {
		*vr->cv = i->volume;
		vr->success = 1;
	}
	pa_threaded_mainloop_signal(mainloop, 0);
}

static int get_volume(int dir, pa_cvolume *cv)
{
	struct volume_ret vr = { .cv = cv };
	uint32_t idx;

	if (dir == PLAY) {
		idx = pa_stream_get_index(stream[PLAY]);
		 EXEC_OP(pa_context_get_sink_input_info,
			 context, idx, play_volume_callback, &vr);
	} else {
		idx = pa_stream_get_device_index(stream[REC]);
		EXEC_OP(pa_context_get_source_info_by_index,
			context, idx, rec_volume_callback, &vr);
	}
	if (!vr.success) {
		warn_pa("failed to get %s volume", dir_str[dir]);
		return -EIO;
	}
	return 0;
}

static int set_volume(int dir, pa_cvolume *cv)
{
	uint32_t idx;
	int rc;

	if (dir == PLAY) {
		idx = pa_stream_get_index(stream[PLAY]);
		rc = EXEC_CONTEXT_OP(pa_context_set_sink_input_volume,
				     context, idx, cv);
	} else {
		idx = pa_stream_get_device_index(stream[REC]);
		rc = EXEC_CONTEXT_OP(pa_context_set_source_volume_by_index,
				     context, idx, cv);
	}
	return rc;
}

static int chan_left_right(int ch)
{
	if (!channel_map || channel_map->channels <= ch) {
		switch (ch) {
		case 0:
			return LEFT;
		case 1:
			return RIGHT;
		default:
			return -1;
		}
	}

	switch (channel_map->map[ch]) {
	case PA_CHANNEL_POSITION_FRONT_LEFT:
	case PA_CHANNEL_POSITION_REAR_LEFT:
	case PA_CHANNEL_POSITION_FRONT_LEFT_OF_CENTER:
	case PA_CHANNEL_POSITION_SIDE_LEFT:
	case PA_CHANNEL_POSITION_TOP_FRONT_LEFT:
	case PA_CHANNEL_POSITION_TOP_REAR_LEFT:
		return LEFT;
	case PA_CHANNEL_POSITION_FRONT_RIGHT:
	case PA_CHANNEL_POSITION_REAR_RIGHT:
	case PA_CHANNEL_POSITION_FRONT_RIGHT_OF_CENTER:
	case PA_CHANNEL_POSITION_SIDE_RIGHT:
	case PA_CHANNEL_POSITION_TOP_FRONT_RIGHT:
	case PA_CHANNEL_POSITION_TOP_REAR_RIGHT:
		return RIGHT;
	default:
		return -1;
	}
}

static int do_mixer(int dir, int *vol)
{
	pa_cvolume cv;
	int i, rc;

	if (vol[0] >= 0) {
		int avg;

		stored_oss_vol[dir][LEFT] = vol[LEFT];
		stored_oss_vol[dir][RIGHT] = vol[RIGHT];
		vol[LEFT] = vol[LEFT] * PA_VOLUME_NORM / 100;
		vol[RIGHT] = vol[RIGHT] * PA_VOLUME_NORM / 100;
		avg = (vol[LEFT] + vol[RIGHT]) / 2;

		pa_cvolume_mute(&cv, sample_spec.channels);

		for (i = 0; i < cv.channels; i++)
			switch (chan_left_right(i)) {
			case LEFT:	cv.values[i] = vol[LEFT];	break;
			case RIGHT:	cv.values[i] = vol[RIGHT];	break;
			default:	cv.values[i] = avg;		break;
			}

		rc = set_volume(dir, &cv);
		if (rc)
			return rc;
	}

	rc = get_volume(dir, &cv);
	if (rc)
		return rc;

	vol[LEFT] = cv.values[0] * 100 / PA_VOLUME_NORM;
	vol[RIGHT] = cv.values[1] * 100 / PA_VOLUME_NORM;
	return 0;
}

static ssize_t padsp_mixer(enum ossp_opcode opcode,
			   void *carg, void *din, size_t din_sz,
			   void *rarg, void *dout, size_t *dout_szp)
{
	struct ossp_mixer_arg *arg = carg;
	int i, rc[2] = { };

	if (prepare_streams())
		return -EIO;

	for (i = 0; i < 2; i++)
		if (stream[i])
			rc[i] = do_mixer(i, arg->vol[i]);
		else
			memset(arg->vol[i], 0, sizeof(arg->vol[i]));

	*(struct ossp_mixer_arg *)rarg = *arg;
	return rc[0] ?: rc[1];
}

static void context_state_callback(pa_context *cxt, void *userdata)
{
	pa_threaded_mainloop_signal(mainloop, 0);
}

static void context_subscribe_callback(pa_context *context,
				       pa_subscription_event_type_t type,
				       uint32_t idx, void *userdata)
{
	struct ossp_notify event = { .magic = OSSP_NOTIFY_MAGIC,
				     .opcode = OSSP_NOTIFY_VOLCHG };
	ssize_t ret;

	if ((type & PA_SUBSCRIPTION_EVENT_TYPE_MASK) !=
	    PA_SUBSCRIPTION_EVENT_CHANGE)
		return;

	ret = write(notify_fd, &event, sizeof(event));
	if (ret != sizeof(event) && errno != EPIPE)
		warn_e(-errno, "write to notify_fd failed");
}

static ssize_t padsp_open(enum ossp_opcode opcode,
			  void *carg, void *din, size_t din_sz,
			  void *rarg, void *dout, size_t *dout_szp)
{
	struct ossp_dsp_open_arg *arg = carg;
	char host_name[128] = "(unknown)", opener[128] = "(unknown)";
	int state;

	switch (arg->flags & O_ACCMODE) {
	case O_WRONLY:
		stream_enabled[PLAY] = 1;
		break;
	case O_RDONLY:
		stream_enabled[REC] = 1;
		break;
	case O_RDWR:
		stream_enabled[PLAY] = 1;
		stream_enabled[REC] = 1;
		break;
	default:
		assert(0);
	}

	/* determine stream name */
	gethostname(host_name, sizeof(host_name) - 1);
	snprintf(stream_name, sizeof(stream_name), "OSS Proxy %s/%s:%ld",
		 host_name, username, (long)arg->opener_pid);

	/* create and connect PA context */
	get_proc_self_info(arg->opener_pid, NULL, opener, sizeof(opener));
	context = pa_context_new(mainloop_api, opener);
	if (!context) {
		err("pa_context_new() failed");
		return -EIO;
	}

	pa_context_set_state_callback(context, context_state_callback, NULL);
	pa_context_set_subscribe_callback(context, context_subscribe_callback,
					  NULL);

	pa_context_connect(context, NULL, 0, NULL);
	while (1) {
		state = pa_context_get_state(context);
		if (state != PA_CONTEXT_CONNECTING &&
		    state != PA_CONTEXT_AUTHORIZING &&
		    state != PA_CONTEXT_SETTING_NAME)
			break;

		pa_threaded_mainloop_wait(mainloop);
	}

	if (EXEC_CONTEXT_OP(pa_context_subscribe, context,
			    PA_SUBSCRIPTION_MASK_SINK_INPUT |
			    PA_SUBSCRIPTION_MASK_SOURCE))
		warn_pa("failed to subscribe to context events");

	if (state != PA_CONTEXT_READY) {
		err_pa("failed to connect context, state=%d", state);
		return -EIO;
	}

	return 0;
}

static void stream_rw_callback(pa_stream *s, size_t length, void *userdata)
{
	size_t size;

	if (s == stream[PLAY])
		size = pa_stream_writable_size(s);
	else
		size = pa_stream_readable_size(s);

	if (size < fragsize)
		return;

	if (stream_waiting)
		pa_threaded_mainloop_signal(mainloop, 0);
	if (stream_notify) {
		struct ossp_notify event = { .magic = OSSP_NOTIFY_MAGIC,
					     .opcode = OSSP_NOTIFY_POLL };
		ssize_t ret;

		ret = write(notify_fd, &event, sizeof(event));
		if (ret != sizeof(event)) {
			if (errno != EPIPE)
				err_e(-errno, "write to notify_fd failed");

			/* This function is run from PA mainloop and
			 * thus the following padsp_done() won't be
			 * noticed before the mainthread tries to run
			 * the next command.  Well, that's good enough.
			 */
			padsp_done();
		}
		stream_notify = 0;
	}
}

static ssize_t padsp_write(enum ossp_opcode opcode,
			   void *carg, void *din, size_t din_sz,
			   void *rarg, void *dout, size_t *dout_szp)
{
	struct ossp_dsp_rw_arg *arg = carg;
	size_t size;

	if (prepare_streams() || !stream[PLAY])
		return -EIO;

	stream_waiting++;
	while (1) {
		size = pa_stream_writable_size(stream[PLAY]);
		if (arg->nonblock || size >= fragsize)
			break;
		pa_threaded_mainloop_wait(mainloop);
	}
	stream_waiting--;

	if (size < fragsize)
		return -EAGAIN;

	size = min(size, din_sz);

	if (pa_stream_write(stream[PLAY], din, size, NULL,
			    0, PA_SEEK_RELATIVE) < 0) {
		err_pa("pa_stream_write() failed");
		return padsp_done();
	}

	return size;
}

static ssize_t padsp_read(enum ossp_opcode opcode,
			  void *carg, void *din, size_t din_sz,
			  void *rarg, void *dout, size_t *dout_szp)
{
	struct ossp_dsp_rw_arg *arg = carg;
	size_t size;

	if (prepare_streams() || !stream[REC])
		return -EIO;
 again:
	stream_waiting++;
	while (1) {
		size = pa_stream_readable_size(stream[REC]) + rec_buf_sz;
		if (arg->nonblock || size >= fragsize)
			break;
		pa_threaded_mainloop_wait(mainloop);
	}
	stream_waiting--;
	if (size < fragsize)
		return -EAGAIN;

	if (rec_buf_sz < max_t(size_t, fragsize, *dout_szp)) {
		const void *peek_data;

		if (pa_stream_peek(stream[REC], &peek_data, &size) < 0) {
			err_pa("pa_stream_peek() failed");
			return padsp_done();
		}

		if (ensure_sbuf_size(&rec_sbuf, rec_buf_sz + size)) {
			err_pa("failed to allocate recording buffer");
			return padsp_done();
		}

		memcpy(rec_sbuf.buf + rec_buf_sz, peek_data, size);
		rec_buf_sz += size;

		pa_stream_drop(stream[REC]);
	}

	/*
	 * Readable size report isn't always reliable and the
	 * following condition somtimes triggers.
	 */
	if (rec_buf_sz < fragsize) {
		if (arg->nonblock)
			return -EAGAIN;
		else
			goto again;
	}

	size = rec_buf_sz / fragsize * fragsize;
	size = min(size, *dout_szp);

	memcpy(dout, rec_sbuf.buf, size);
	memmove(rec_sbuf.buf, rec_sbuf.buf + size, rec_buf_sz - size);
	rec_buf_sz -= size;

	*dout_szp = size;
	return size;
}

static ssize_t padsp_poll(enum ossp_opcode opcode,
			  void *carg, void *din, size_t din_sz,
			  void *rarg, void *dout, size_t *dout_szp)
{
	unsigned revents = 0;

	if (prepare_streams() < 0)
		return -EIO;

	stream_notify |= *(int *)carg;

	if (stream[PLAY] && pa_stream_writable_size(stream[PLAY]))
		revents |= POLLOUT;
	if (stream[REC] && pa_stream_readable_size(stream[REC]))
		revents |= POLLIN;

	*(unsigned *)rarg = revents;
	return 0;
}

static ssize_t padsp_flush(enum ossp_opcode opcode,
			   void *carg, void *din, size_t din_sz,
			   void *rarg, void *dout, size_t *dout_szp)
{
	flush_streams(opcode == OSSP_DSP_SYNC);
	return 0;
}

static ssize_t padsp_post(enum ossp_opcode opcode,
			  void *carg, void *din, size_t din_sz,
			  void *rarg, void *dout, size_t *dout_szp)
{
	if (stream[PLAY])
		return EXEC_STREAM_OP(pa_stream_trigger, stream[PLAY]);
	return 0;
}

static ssize_t padsp_get_param(enum ossp_opcode opcode,
			       void *carg, void *din, size_t din_sz,
			       void *rarg, void *dout, size_t *dout_szp)
{
	int v = 0;

	switch (opcode) {
	case OSSP_DSP_GET_RATE:
		v = sample_spec.rate;
		break;

	case OSSP_DSP_GET_CHANNELS:
		v = sample_spec.channels;
		break;

	case OSSP_DSP_GET_FORMAT:
		v = fmt_pa_to_oss(sample_spec.format);
		break;

	case OSSP_DSP_GET_BLKSIZE:
		if (prepare_streams() < 0)
			return -EIO;
		v = fragsize;
		break;

	case OSSP_DSP_GET_FORMATS:
		v = AFMT_U8 | AFMT_A_LAW | AFMT_MU_LAW | AFMT_S16_LE |
			AFMT_S16_BE | AFMT_FLOAT | AFMT_S32_LE | AFMT_S32_BE;
		break;

	case OSSP_DSP_GET_TRIGGER:
		if (!stream_corked[PLAY])
			v |= PCM_ENABLE_OUTPUT;
		if (!stream_corked[REC])
			v |= PCM_ENABLE_INPUT;
		break;

	default:
		assert(0);
	}

	*(int *)rarg = v;

	return 0;
}

static ssize_t padsp_set_param(enum ossp_opcode opcode,
			       void *carg, void *din, size_t din_sz,
			       void *rarg, void *dout, size_t *dout_szp)
{
	pa_sample_spec new_spec = sample_spec;
	int v = *(int *)carg;

	/* kill the streams before changing parameters */
	kill_streams();

	switch (opcode) {
	case OSSP_DSP_SET_RATE:
		new_spec.rate = v;
		if (pa_sample_spec_valid(&new_spec))
			sample_spec = new_spec;
		v = sample_spec.rate;
		break;
	case OSSP_DSP_SET_CHANNELS:
		new_spec.channels = v;
		if (pa_sample_spec_valid(&new_spec))
			sample_spec = new_spec;
		v = sample_spec.channels;
		break;
	case OSSP_DSP_SET_FORMAT:
		new_spec.format = fmt_oss_to_pa(v);
		if (pa_sample_spec_valid(&new_spec))
			sample_spec = new_spec;
		v = fmt_pa_to_oss(sample_spec.format);
		break;
	case OSSP_DSP_SET_SUBDIVISION:
		if (!v) {
			v = subdivision ?: 1;
			break;
		}
		if (subdivision || fragshift)
			return -EINVAL;
		if (subdivision != 1 && subdivision != 2 && subdivision != 4 &&
		    subdivision != 8 && subdivision != 16)
			return -EINVAL;
		subdivision = v;
		break;
	case OSSP_DSP_SET_FRAGMENT:
		if (subdivision || fragshift)
			return -EINVAL;
		fragshift = v & 0xffff;
		maxfrags = (v >> 16) & 0xffff;
		if (fragshift < 4)
			fragshift = 4;
		if (maxfrags < 2)
			maxfrags = 2;
		break;
	default:
		assert(0);
	}

	if (rarg)
		*(int *)rarg = v;
	return 0;
}

static ssize_t padsp_set_trigger(enum ossp_opcode opcode,
				 void *carg, void *din, size_t din_sz,
				 void *rarg, void *dout, size_t *dout_szp)
{
	int enable = *(int *)carg;
	int i;

	stream_corked[PLAY] = (enable & PCM_ENABLE_OUTPUT) ? 0 : 1;
	stream_corked[REC] = (enable & PCM_ENABLE_INPUT) ? 0 : 1;

	for (i = 0; i < 2; i++) {
		if (!stream[i])
			continue;

		if (i == PLAY && !stream_corked[i])
			EXEC_STREAM_OP(pa_stream_trigger, stream[i]);
		else
			EXEC_STREAM_OP(pa_stream_cork, stream[i],
				       stream_corked[i]);
	}

	return 0;
}

static ssize_t padsp_get_space(enum ossp_opcode opcode,
			       void *carg, void *din, size_t din_sz,
			       void *rarg, void *dout, size_t *dout_szp)
{
	int dir = (opcode == OSSP_DSP_GET_OSPACE) ? PLAY : REC;
	size_t space;
	struct audio_buf_info info = { };

	if (prepare_streams() < 0 || !stream[dir])
		return -EIO;

	if (dir == PLAY)
		space = pa_stream_writable_size(stream[PLAY]);
	else
		space = pa_stream_readable_size(stream[REC]);

	info.fragments = space / fragsize;
	info.fragstotal = maxfrags;
	info.fragsize = fragsize;
	info.bytes = space;

	*(struct audio_buf_info *)rarg = info;
	return 0;
}

static ssize_t padsp_get_ptr(enum ossp_opcode opcode,
			     void *carg, void *din, size_t din_sz,
			     void *rarg, void *dout, size_t *dout_szp)
{
	int dir = (opcode == OSSP_DSP_GET_OPTR) ? PLAY : REC;
	size_t buf_size = maxfrags * fragsize;
	size_t frame_size = pa_frame_size(&sample_spec);
	double bpus = (double)pa_bytes_per_second(&sample_spec) / 1000000;
	size_t bytes, delta_bytes;
	pa_usec_t usec, delta;
	struct count_info info = { };

	if (prepare_streams() < 0 || !stream[dir])
		return -EIO;

	if (pa_stream_get_time(stream[dir], &usec) < 0) {
		warn_pa("pa_stream_get_time() failed");
		return -EIO;
	}

	delta = usec - stream_ptr_timestamp[dir];
	stream_ptr_timestamp[dir] = usec;
	bytes = bpus * usec;
	delta_bytes = bpus * delta;

	info.bytes = bytes & INT_MAX;
	info.blocks = (delta_bytes + frame_size - 1) / frame_size;
	info.ptr = bytes % buf_size;

	*(struct count_info *)rarg = info;
	return 0;
}

static ssize_t padsp_get_odelay(enum ossp_opcode opcode,
				void *carg, void *din, size_t din_sz,
				void *rarg, void *dout, size_t *dout_szp)
{
	double bpus = (double)pa_bytes_per_second(&sample_spec) / 1000000;
	pa_usec_t usec;

	if (prepare_streams() < 0 || !stream[PLAY])
		return -EIO;

	if (pa_stream_get_latency(stream[PLAY], &usec, NULL) < 0) {
		warn_pa("pa_stream_get_latency() failed");
		return -EIO;
	}

	*(int *)rarg = bpus * usec;
	return 0;
}

static ossp_action_fn_t action_fn_tbl[OSSP_NR_OPCODES] = {
	[OSSP_MIXER]		= padsp_mixer,
	[OSSP_DSP_OPEN]		= padsp_open,
	[OSSP_DSP_READ]		= padsp_read,
	[OSSP_DSP_WRITE]	= padsp_write,
	[OSSP_DSP_POLL]		= padsp_poll,
	[OSSP_DSP_RESET]	= padsp_flush,
	[OSSP_DSP_SYNC]		= padsp_flush,
	[OSSP_DSP_POST]		= padsp_post,
	[OSSP_DSP_GET_RATE]	= padsp_get_param,
	[OSSP_DSP_GET_CHANNELS]	= padsp_get_param,
	[OSSP_DSP_GET_FORMAT]	= padsp_get_param,
	[OSSP_DSP_GET_BLKSIZE]	= padsp_get_param,
	[OSSP_DSP_GET_FORMATS]	= padsp_get_param,
	[OSSP_DSP_SET_RATE]	= padsp_set_param,
	[OSSP_DSP_SET_CHANNELS]	= padsp_set_param,
	[OSSP_DSP_SET_FORMAT]	= padsp_set_param,
	[OSSP_DSP_SET_SUBDIVISION] = padsp_set_param,
	[OSSP_DSP_SET_FRAGMENT]	= padsp_set_param,
	[OSSP_DSP_GET_TRIGGER]	= padsp_get_param,
	[OSSP_DSP_SET_TRIGGER]	= padsp_set_trigger,
	[OSSP_DSP_GET_OSPACE]	= padsp_get_space,
	[OSSP_DSP_GET_ISPACE]	= padsp_get_space,
	[OSSP_DSP_GET_OPTR]	= padsp_get_ptr,
	[OSSP_DSP_GET_IPTR]	= padsp_get_ptr,
	[OSSP_DSP_GET_ODELAY]	= padsp_get_odelay,
};

static int action_pre(void)
{
	pa_threaded_mainloop_lock(mainloop);
	if (fail_code) {
		pa_threaded_mainloop_unlock(mainloop);
		return fail_code;
	}
	return 0;
}

static void action_post(void)
{
	pa_threaded_mainloop_unlock(mainloop);
}

int main(int argc, char **argv)
{
	struct passwd *pw, pw_buf;
	char pw_sbuf[sysconf(_SC_GETPW_R_SIZE_MAX)];
	struct sigaction sa;
	int opt, rc;

	snprintf(username, sizeof(username), "uid%d", getuid());
	if (getpwuid_r(getuid(), &pw_buf, pw_sbuf, sizeof(pw_sbuf), &pw) == 0)
		snprintf(username, sizeof(username), "%s", pw->pw_name);

	snprintf(ossp_log_name, sizeof(ossp_log_name), "ossp-padsp[%s:%d]",
		 username, getpid());

	while ((opt = getopt(argc, argv, "c:r:n:l:t")) != -1) {
		switch (opt) {
		case 'c':
			cmd_fd = atoi(optarg);
			break;
		case 'r':
			reply_fd = atoi(optarg);
			break;
		case 'n':
			notify_fd = atoi(optarg);
			break;
		case 'l':
			ossp_log_level = atoi(optarg);
			break;
		case 't':
			ossp_log_timestamp = 1;
			break;
		}
	}

	if (cmd_fd < 0 || reply_fd < 0 || notify_fd < 0) {
		fprintf(stderr, usage);
		return 1;
	}

	memset(&sa, 0, sizeof(sa));
	sa.sa_handler = SIG_IGN;
	if (sigaction(SIGPIPE, &sa, NULL)) {
		err_e(-errno, "failed to ignore SIGPIPE");
		return 1;
	}

	mainloop = pa_threaded_mainloop_new();
	if (!mainloop) {
		err("failed to allocate mainloop");
		return 1;
	}
	mainloop_api = pa_threaded_mainloop_get_api(mainloop);

	if (pa_threaded_mainloop_start(mainloop)) {
		err("pa_mainloop_start() failed");
		return 1;
	}

	/* Okay, now we're open for business */
	rc = 0;
	do {
		rc = ossp_slave_process_command(cmd_fd, reply_fd, action_fn_tbl,
						action_pre, action_post);
	} while (rc > 0 && !fail_code);
	if (rc)
		fail_code = rc;

	pa_threaded_mainloop_lock(mainloop);

	kill_streams();
	if (context) {
		pa_context_disconnect(context);
		pa_context_unref(context);
	}

	pa_threaded_mainloop_unlock(mainloop);

	pa_threaded_mainloop_stop(mainloop);
	pa_threaded_mainloop_free(mainloop);

	return fail_code ? 1 : 0;
}
