/*
 * ossp-padsp - ossp DSP slave which forwards to pulseaduio
 *
 * Copyright (C) 2008-2010  SUSE Linux Products GmbH
 * Copyright (C) 2008-2010  Tejun Heo <tj@kernel.org>
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
#include <stdarg.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include <pulse/pulseaudio.h>
#include <sys/soundcard.h>

#include "ossp-slave.h"

enum {
	AFMT_FLOAT		= 0x00004000,
	AFMT_S32_LE		= 0x00001000,
	AFMT_S32_BE		= 0x00002000,
};

/* everything is in millisecs */
struct stream_params {
	size_t		min_process;
	size_t		min_latency;
	size_t		dfl_process;
	size_t		dfl_latency;
	size_t		mmap_process;
	size_t		mmap_latency;
	size_t		mmap_lead;
	size_t		mmap_staging;
};

/* TODO: make this configurable */
static struct stream_params stream_params[] = {
	[ PLAY ] = { .min_process = 25,		.min_latency = 100,
		     .dfl_process = 50,		.dfl_latency = 200,
		     .mmap_process = 25,	.mmap_latency = 50,
		     .mmap_lead = 25,		.mmap_staging = 100 },
	[ REC ]	 = { .min_process = 25,		.min_latency = 200,
		     .dfl_process = 50,		.dfl_latency = 400,
		     .mmap_process = 25,	.mmap_latency = 50,
		     .mmap_lead = 25,		.mmap_staging = 1000 },
};

static size_t page_size;
static pa_context *context;
static pa_threaded_mainloop *mainloop;
static pa_mainloop_api *mainloop_api;
static char stream_name[128];
static int stream_enabled[2];
static int stream_corked[2];
static int stream_waiting;
static int stream_notify;
static pa_channel_map channel_map_stor;
static pa_channel_map *channel_map;
static pa_stream *stream[2];
static pa_usec_t stream_ptr_timestamp[2];
static struct ring_buf rec_buf;
static int stored_oss_vol[2][2] = { { -1, -1 }, { -1, -1 } };
static int fail_code;

static pa_sample_spec sample_spec = {
	.format = PA_SAMPLE_U8,
	.rate = 8000,
	.channels = 1,
};
static size_t sample_bps = 8000;
static size_t frame_size = 1;

/* user visible stream parameters */
static size_t user_frag_size;
static size_t user_subdivision;	/* alternative way to determine frag_size */
static size_t user_max_frags;	/* maximum number of fragments */
static size_t user_max_length;

/* actual stream parameters */
static size_t frag_size;
static size_t target_length;
static size_t max_length;
static size_t prebuf_size;

/* mmap stuff */
static size_t mmap_raw_size, mmap_size;
static void *mmap_map[2];
static uint64_t mmap_idx[2];		/* mmap pointer */
static uint64_t mmap_last_idx[2];	/* last idx for get_ptr */
static struct ring_buf mmap_stg[2];	/* staging ring buffer */
static size_t mmap_lead[2];		/* lead bytes */
static int mmap_sync[2];		/* sync with backend stream */

static const char *dir_str[] = {
	[PLAY]		= "PLAY",
	[REC]		= "REC",
};

static void stream_rw_callback(pa_stream *s, size_t length, void *userdata);

#define __pa_err		pa_strerror(pa_context_errno(context))
#define dbg1_pa(fmt, args...)	dbg1(fmt" (%s)" , ##args, __pa_err)
#define dbg0_pa(fmt, args...)	dbg0(fmt" (%s)" , ##args, __pa_err)
#define info_pa(fmt, args...)	info(fmt" (%s)" , ##args, __pa_err)
#define warn_pa(fmt, args...)	warn(fmt" (%s)" , ##args, __pa_err)
#define err_pa(fmt, args...)	err(fmt" (%s)" , ##args, __pa_err)

#define round_down(v, t)	((v) / (t) * (t))
#define round_up(v, t)		(((v) + (t) - 1) / (t) * (t))
#define is_power2(v)		!((v) & ((v) - 1))

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

static int mmapped(void)
{
	return mmap_map[PLAY] || mmap_map[REC];
}

static uint64_t get_mmap_idx(int dir)
{
	uint64_t idx;
	pa_usec_t time;

	if (!stream[dir])
		return mmap_idx[dir];

	if (pa_stream_get_time(stream[dir], &time) < 0) {
		dbg1_pa("pa_stream_get_time() failed");
		return mmap_idx[dir];
	}

	/* calculate the current index from time elapsed */
	idx = ((uint64_t)time * sample_bps / 1000000);
	/* round down to the nearest frame boundary */
	idx = idx / frame_size * frame_size;

	return idx;
}

static void flush_streams(int drain)
{
	int i;

	if (!(stream[PLAY] || stream[REC]))
		return;

	dbg0("FLUSH drain=%d", drain);

	/* mmapped streams run forever, can't drain */
	if (drain && !mmapped() && stream[PLAY])
		EXEC_STREAM_OP(pa_stream_drain, stream[PLAY]);

	for (i = 0; i < 2; i++)
		if (stream[i])
			EXEC_STREAM_OP(pa_stream_flush, stream[i]);

	ring_consume(&rec_buf, ring_bytes(&rec_buf));
}

static void kill_streams(void)
{
	int dir;

	if (!(stream[PLAY] || stream[REC]))
		return;

	flush_streams(1);

	dbg0("KILL");

	for (dir = 0; dir < 2; dir++) {
		if (!stream[dir])
			continue;
		pa_stream_disconnect(stream[dir]);
		pa_stream_unref(stream[dir]);
		stream[dir] = NULL;
		stream_ptr_timestamp[dir] = 0;

		ring_consume(&mmap_stg[dir], ring_bytes(&mmap_stg[dir]));
		ring_resize(&mmap_stg[dir], 0);
	}
}

static int trigger_streams(int play, int rec)
{
	int ret = 0, dir, rc;

	if (play >= 0)
		stream_corked[PLAY] = !play;
	if (rec >= 0)
		stream_corked[REC] = !rec;

	for (dir = 0; dir < 2; dir++) {
		if (!stream[dir])
			continue;

		rc = EXEC_STREAM_OP(pa_stream_cork, stream[dir],
				    stream_corked[dir]);
		if (!rc && dir == PLAY && !mmap_map[dir] && !stream_corked[dir])
			rc = EXEC_STREAM_OP(pa_stream_trigger, stream[dir]);
		if (!ret)
			ret = rc;
	}

	return ret;
}

static void stream_state_callback(pa_stream *s, void *userdata)
{
	pa_threaded_mainloop_signal(mainloop, 0);
}

static void stream_underflow_callback(pa_stream *s, void *userdata)
{
	int dir = (s == stream[PLAY]) ? PLAY : REC;

	dbg0("%s stream underrun", dir_str[dir]);
}

static void stream_overflow_callback(pa_stream *s, void *userdata)
{
	int dir = (s == stream[PLAY]) ? PLAY : REC;

	dbg0("%s stream overrun", dir_str[dir]);
}

static size_t duration_to_bytes(size_t dur)
{
	return round_up(dur * sample_bps / 1000, frame_size);
}

static int prepare_streams(void)
{
	const struct stream_params *sp;
	size_t min_frag_size, min_target_length, tmp;
	int dir, rc;

	/* nothing to do? */
	if ((!stream_enabled[PLAY] || stream[PLAY]) &&
	    (!stream_enabled[REC] || stream[REC]))
		return 0;

	/* determine sample parameters */
	sample_bps = pa_bytes_per_second(&sample_spec);
	frame_size = pa_frame_size(&sample_spec);

	sp = &stream_params[PLAY];
	if (stream_enabled[REC])
		sp = &stream_params[REC];

	min_frag_size = duration_to_bytes(sp->min_process);
	min_target_length = duration_to_bytes(sp->min_latency);

	/* determine frag_size */
	if (user_frag_size % frame_size) {
		warn("requested frag_size (%zu) isn't multiple of frame (%zu)",
		     user_frag_size, frame_size);
		user_frag_size = round_up(user_frag_size, frame_size);
	}

	if (user_subdivision)
		user_frag_size = round_up(sample_bps / user_subdivision,
					  frame_size);

	if (user_frag_size) {
		frag_size = user_frag_size;
		if (frag_size < min_frag_size) {
			dbg0("requested frag_size (%zu) is smaller than "
			     "minimum (%zu)", frag_size, min_frag_size);
			frag_size = min_frag_size;
		}
	} else {
		tmp = round_up(sp->dfl_process * sample_bps / 1000, frame_size);
		frag_size = tmp;
		/* if frame_size is power of two, make frag_size so too */
		if (is_power2(frame_size)) {
			frag_size = frame_size;
			while (frag_size < tmp)
				frag_size <<= 1;
		}
		user_frag_size = frag_size;
	}

	/* determine target and max length */
	if (user_max_frags) {
		target_length = user_max_frags * user_frag_size;
		if (target_length < min_target_length) {
			dbg0("requested target_length (%zu) is smaller than "
			     "minimum (%zu)", target_length, min_target_length);
			target_length = min_target_length;
		}
	} else {
		tmp = round_up(sp->dfl_latency * sample_bps / 1000, frag_size);
		target_length = tmp;
		/* if frag_size is power of two, make target_length so
		 * too and align it to page_size.
		 */
		if (is_power2(frag_size)) {
			target_length = frag_size;
			while (target_length < max(tmp, page_size))
				target_length <<= 1;
		}
		user_max_frags = target_length / frag_size;
	}

	user_max_length = user_frag_size * user_max_frags;
	max_length = target_length + 2 * frag_size;

	/* If mmapped, create backend stream with fixed parameters to
	 * create illusion of hardware buffer with acceptable latency.
	 */
	if (mmapped()) {
		/* set parameters for backend streams */
		frag_size = duration_to_bytes(sp->mmap_process);
		target_length = duration_to_bytes(sp->mmap_latency);
		max_length = target_length + frag_size;
		prebuf_size = 0;

		mmap_size = round_down(mmap_raw_size, frame_size);
		if (mmap_size != mmap_raw_size)
			warn("mmap_raw_size (%zu) unaligned to frame_size "
			     "(%zu), mmap_size adjusted to %zu",
			     mmap_raw_size, frame_size, mmap_size);
	} else {
		prebuf_size = min(user_frag_size * 2, user_max_length / 2);
		prebuf_size = round_down(prebuf_size, frame_size);
	}

	for (dir = 0; dir < 2; dir++) {
		pa_buffer_attr new_ba = { };
		char buf[128];
		pa_stream *s;
		pa_stream_flags_t flags;
		int vol[2];
		size_t size;

		if (!stream_enabled[dir] || stream[dir])
			continue;

		dbg0("CREATE %s %s fsz=%zu:%zu", dir_str[dir],
		     pa_sample_spec_snprint(buf, sizeof(buf), &sample_spec),
		     frag_size, frag_size * 1000 / sample_bps);
		dbg0("  tlen=%zu:%zu max=%zu:%zu pre=%zu:%zu",
		     target_length, target_length * 1000 / sample_bps,
		     max_length, max_length * 1000 / sample_bps,
		     prebuf_size, prebuf_size * 1000 / sample_bps);
		dbg0("  u_sd=%zu u_fsz=%zu:%zu u_maxf=%zu",
		     user_subdivision, user_frag_size,
		     user_frag_size * 1000 / sample_bps, user_max_frags);

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
		if (dir == PLAY) {
			pa_stream_set_write_callback(s,
					stream_rw_callback, NULL);
			pa_stream_set_underflow_callback(s,
					stream_underflow_callback, NULL);
		} else {
			pa_stream_set_read_callback(s,
					stream_rw_callback, NULL);
			pa_stream_set_overflow_callback(s,
					stream_overflow_callback, NULL);
		}

		flags = PA_STREAM_AUTO_TIMING_UPDATE |
			PA_STREAM_INTERPOLATE_TIMING;
		if (stream_corked[dir])
			flags |= PA_STREAM_START_CORKED;

		new_ba.maxlength = max_length;
		new_ba.tlength = target_length;
		new_ba.prebuf = prebuf_size;
		new_ba.minreq = frag_size;
		new_ba.fragsize = frag_size;

		if (dir == PLAY) {
			if (pa_stream_connect_playback(s, NULL, &new_ba, flags,
						       NULL, NULL)) {
				err_pa("failed to connect playback stream");
				goto fail;
			}
		} else {
			if (pa_stream_connect_record(s, NULL, &new_ba, flags)) {
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

		/* apply stored OSS volume */
		memcpy(vol, stored_oss_vol[dir], sizeof(vol));
		if (do_mixer(dir, vol))
			warn_pa("initial volume control failed");

		/* stream is ready setup mmap stuff */
		if (!mmap_map[dir])
			continue;

		/* prep mmap staging buffer */
		size = round_up(sp->mmap_staging * sample_bps / 1000,
				frag_size);
		rc = ring_resize(&mmap_stg[dir], size);
		if (rc)
			return rc;

		mmap_idx[dir] = mmap_last_idx[dir] = get_mmap_idx(dir);
		mmap_lead[dir] = round_up(sp->mmap_lead * sample_bps / 1000,
					  frame_size);
		mmap_sync[dir] = 1;

		/* apply the current trigger settings */
		trigger_streams(-1, -1);
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
	/*case PA_CHANNEL_POSITION_LEFT:*/	/* same as FRONT_LEFT */
	case PA_CHANNEL_POSITION_FRONT_LEFT:
	case PA_CHANNEL_POSITION_REAR_LEFT:
	case PA_CHANNEL_POSITION_FRONT_LEFT_OF_CENTER:
	case PA_CHANNEL_POSITION_SIDE_LEFT:
	case PA_CHANNEL_POSITION_TOP_FRONT_LEFT:
	case PA_CHANNEL_POSITION_TOP_REAR_LEFT:
		return LEFT;
	/*case PA_CHANNEL_POSITION_RIGHT:*/	/* same as FRONT_RIGHT */
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
	unsigned lv, rv;
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

	if (cv.channels == 1)
		lv = rv = pa_cvolume_avg(&cv);
	else {
		unsigned lcnt = 0, rcnt = 0;

		for (i = 0, lv = 0, rv = 0; i < cv.channels; i++)
			switch (chan_left_right(i)) {
			case LEFT:	lv += cv.values[i];	lcnt++;	break;
			case RIGHT:	rv += cv.values[i];	rcnt++;	break;
			}

		if (lcnt)
			lv /= lcnt;
		if (rcnt)
			rv /= rcnt;
	}

	vol[LEFT] = lv * 100 / PA_VOLUME_NORM;
	vol[RIGHT] = rv * 100 / PA_VOLUME_NORM;

	return 0;
}

static ssize_t padsp_mixer(enum ossp_opcode opcode,
			   void *carg, void *din, size_t din_sz,
			   void *rarg, void *dout, size_t *dout_szp, int tfd)
{
	struct ossp_mixer_arg *arg = carg;
	int i, rc[2] = { };

	if (prepare_streams())
		return -EIO;

	for (i = 0; i < 2; i++)
		if (stream[i])
			rc[i] = do_mixer(i, arg->vol[i]);
		else
			memset(arg->vol[i], -1, sizeof(arg->vol[i]));

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

	ret = write(ossp_notify_fd, &event, sizeof(event));
	if (ret != sizeof(event) && errno != EPIPE)
		warn_e(-errno, "write to notify_fd failed");
}

static ssize_t padsp_open(enum ossp_opcode opcode,
			  void *carg, void *din, size_t din_sz,
			  void *rarg, void *dout, size_t *dout_szp, int tfd)
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
		 host_name, ossp_user_name, (long)arg->opener_pid);

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

static void mmap_fill_pstg(void)
{
	struct ring_buf *stg = &mmap_stg[PLAY];
	struct ring_buf mmap;
	uint64_t new_idx = get_mmap_idx(PLAY);
	size_t bytes, space, size;
	void *data;

	if (new_idx <= mmap_idx[PLAY])
		return;

	bytes = new_idx - mmap_idx[PLAY];
	space = ring_space(stg);

	if (bytes > mmap_size) {
		dbg0("mmap playback transfer chunk bigger than "
		     "mmap size (bytes=%zu mmap_size=%zu)", bytes, mmap_size);
		mmap_sync[PLAY] = 1;
		bytes = mmap_size;
	}

	if (bytes > space) {
		dbg0("mmap playback staging buffer overflow "
		     "(bytes=%zu space=%zu)", bytes, space);
		mmap_sync[PLAY] = 1;
		bytes = space;
	}

	ring_manual_init(&mmap, mmap_map[PLAY], mmap_size,
			 new_idx % mmap_size, bytes);

	while ((data = ring_data(&mmap, &size))) {
		ring_fill(stg, data, size);
		ring_consume(&mmap, size);
	}

	mmap_idx[PLAY] = new_idx;
}

static void mmap_consume_rstg(void)
{
	struct ring_buf *stg = &mmap_stg[REC];
	struct ring_buf mmap;
	uint64_t new_idx = get_mmap_idx(REC);
	uint64_t fill_idx = mmap_idx[REC];
	size_t bytes, space;

	if (new_idx <= mmap_idx[REC])
		return;

	space = new_idx - mmap_idx[REC];	/* mmapped space to fill in */
	bytes = ring_bytes(stg);		/* recorded bytes in staging */ 

	if (space > bytes) {
		if (!mmap_sync[REC])
			dbg0("mmap recording staging buffer underflow "
			     "(space=%zu bytes=%zu)", space, bytes);
		mmap_sync[REC] = 1;
	}

	if (space > mmap_size) {
		if (!mmap_sync[REC])
			dbg0("mmap recording transfer chunk bigger than "
			     "mmap size (space=%zu mmap_size=%zu)",
			     bytes, mmap_size);
		mmap_sync[REC] = 1;
		space = mmap_size;
	}

	/* If resync is requested, leave lead bytes in the staging
	 * buffer and copy everything else such that data is filled
	 * upto the new_idx.  If there are more bytes in staging than
	 * available space, those will be dropped.
	 */
	if (mmap_sync[REC]) {
		ssize_t avail = bytes - mmap_lead[REC];

		/* make sure we always have lead bytes in staging */
		if (avail < 0)
			goto skip;

		if (avail > space) {
			dbg0("dropping %zu bytes from record staging buffer",
			     avail - space);
			ring_consume(&mmap_stg[REC], avail - space);
			avail = space;
		} else {
			dbg0("skippping %zu bytes in record mmap map",
			     space - avail);
			space = avail;
		}

		assert(new_idx >= avail);
		fill_idx = new_idx - avail;
		mmap_sync[REC] = 0;
	}

	ring_manual_init(&mmap, mmap_map[REC], mmap_size,
			 fill_idx % mmap_size, 0);

	while (space) {
		void *data;
		size_t size, todo;

		data = ring_data(stg, &size);
		assert(data);

		todo = min(size, space);
		ring_fill(&mmap, data, todo);

		ring_consume(stg, todo);
		space -= todo;
	}

 skip:
	mmap_idx[REC] = new_idx;
}

static void do_mmap_write(size_t space)
{
	struct ring_buf *stg = &mmap_stg[PLAY];
	size_t todo;
	void *data;

	space = round_down(space, frame_size);
	mmap_fill_pstg();

	while (space && (data = ring_data(stg, &todo))) {
		pa_seek_mode_t mode = PA_SEEK_RELATIVE_END;
		int64_t offset = 0;

		todo = min(todo, space);

		if (mmap_sync[PLAY]) {
			mode = PA_SEEK_RELATIVE_ON_READ;
			offset = (int64_t)mmap_lead[PLAY] - ring_bytes(stg);
			dbg0("mmap resync, offset=%ld", (long)offset);
		}

		if (pa_stream_write(stream[PLAY], data, todo, NULL,
				    offset, mode) < 0) {
			err_pa("pa_stream_write() failed");
			padsp_done();
			return;
		}

		mmap_sync[PLAY] = 0;
		ring_consume(stg, todo);
		space -= todo;
	}
}

static void do_mmap_read(size_t bytes)
{
	struct ring_buf *stg = &mmap_stg[REC];

	bytes = round_down(bytes, frame_size);
	mmap_consume_rstg();

	while (bytes) {
		const void *peek_data;
		size_t size;

		if (pa_stream_peek(stream[REC], &peek_data, &size)) {
			err_pa("pa_stream_peek() failed");
			padsp_done();
			return;
		}

		if (!peek_data)
			break;

		if (size <= ring_space(stg))
			ring_fill(stg, peek_data, size);
		else {
			if (!mmap_sync[REC])
				dbg0("recording staging buffer overflow, "
				     "requesting resync");
			mmap_sync[REC] = 1;
		}

		pa_stream_drop(stream[REC]);
		bytes -= size;
	}
}

static void stream_rw_callback(pa_stream *s, size_t length, void *userdata)
{
	size_t size;

	if (s == stream[PLAY]) {
		size = pa_stream_writable_size(s);
		if (mmap_map[PLAY])
			do_mmap_write(size);
	} else if (s == stream[REC]) {
		size = pa_stream_readable_size(s);
		if (mmap_map[REC])
			do_mmap_read(size);
	} else {
		dbg0("stream_rw_callback(): unknown stream %p PLAY/REC=%p/%p\n",
		     s, stream[PLAY], stream[REC]);
		return;
	}

	if (size < user_frag_size)
		return;
	if (stream_waiting)
		pa_threaded_mainloop_signal(mainloop, 0);
	if (stream_notify) {
		struct ossp_notify event = { .magic = OSSP_NOTIFY_MAGIC,
					     .opcode = OSSP_NOTIFY_POLL };
		ssize_t ret;

		ret = write(ossp_notify_fd, &event, sizeof(event));
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
			   void *rarg, void *dout, size_t *dout_szp, int tfd)
{
	struct ossp_dsp_rw_arg *arg = carg;
	size_t size;

	if (prepare_streams() || !stream[PLAY])
		return -EIO;

	stream_waiting++;
	while (1) {
		size = pa_stream_writable_size(stream[PLAY]);
		if (arg->nonblock || size >= user_frag_size)
			break;
		pa_threaded_mainloop_wait(mainloop);
	}
	stream_waiting--;

	size = round_down(size, user_frag_size);
	if (!size)
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
			  void *rarg, void *dout, size_t *dout_szp, int tfd)
{
	struct ossp_dsp_rw_arg *arg = carg;
	size_t size;
	void *data;

	if (prepare_streams() || !stream[REC])
		return -EIO;
 again:
	if (!arg->nonblock) {
		stream_waiting++;
		while (1) {
			size = pa_stream_readable_size(stream[REC]);
			if (size + ring_bytes(&rec_buf) >= user_frag_size)
				break;
			pa_threaded_mainloop_wait(mainloop);
		}
		stream_waiting--;
	}

	while (ring_bytes(&rec_buf) < max(user_frag_size, *dout_szp)) {
		const void *peek_data;

		if (pa_stream_peek(stream[REC], &peek_data, &size) < 0) {
			err_pa("pa_stream_peek() failed");
			return padsp_done();
		}

		if (!peek_data)
			break;

		if (ring_space(&rec_buf) < size) {
			size_t bufsz;

			bufsz = ring_size(&rec_buf);
			bufsz = max(2 * bufsz, bufsz + 2 * size);

			if (ring_resize(&rec_buf, bufsz)) {
				err("failed to allocate recording buffer");
				return padsp_done();
			}
		}

		ring_fill(&rec_buf, peek_data, size);
		pa_stream_drop(stream[REC]);
	}

	size = round_down(ring_bytes(&rec_buf), user_frag_size);
	if (!size) {
		if (arg->nonblock)
			return -EAGAIN;
		else
			goto again;
	}

	*dout_szp = size = min(size, *dout_szp);

	while (size) {
		size_t cnt;

		data = ring_data(&rec_buf, &cnt);
		assert(data);

		cnt = min(size, cnt);
		memcpy(dout, data, cnt);
		ring_consume(&rec_buf, cnt);
		dout += cnt;
		size -= cnt;
	}

	return *dout_szp;
}

static ssize_t padsp_poll(enum ossp_opcode opcode,
			  void *carg, void *din, size_t din_sz,
			  void *rarg, void *dout, size_t *dout_szp, int tfd)
{
	unsigned revents = 0;

	if (prepare_streams() < 0)
		return -EIO;

	stream_notify |= *(int *)carg;

	if (stream[PLAY] &&
	    pa_stream_writable_size(stream[PLAY]) >= user_frag_size)
		revents |= POLLOUT;
	if (stream[REC] &&
	    pa_stream_readable_size(stream[REC]) >= user_frag_size)
		revents |= POLLIN;

	*(unsigned *)rarg = revents;
	return 0;
}

static ssize_t padsp_mmap(enum ossp_opcode opcode,
			  void *carg, void *din, size_t din_sz,
			  void *rarg, void *dout, size_t *dout_szp, int tfd)
{
	struct ossp_dsp_mmap_arg *arg = carg;
	int dir = arg->dir;

	assert(!mmap_map[dir]);

	kill_streams();

	/* arg->size is rounded up to the nearest page boundary.
	 * There is no way to tell what the actual requested value is
	 * but assume that it was the reported buffer space if it
	 * falls into the same page aligned range.
	 */
	mmap_raw_size = arg->size;
	if (user_max_length && user_max_length < mmap_raw_size &&
	    round_up(mmap_raw_size, page_size) ==
	    round_up(user_max_length, page_size)) {
		info("MMAP adjusting raw_size %zu -> %zu",
		     mmap_raw_size, user_max_length);
		mmap_raw_size = user_max_length;
	}

	dbg0("MMAP server-addr=%p sz=%zu", ossp_mmap_addr[dir], mmap_raw_size);

	mmap_map[dir] = ossp_mmap_addr[dir];

	/* if mmapped, only mmapped streams are enabled */
	stream_enabled[PLAY] = !!mmap_map[PLAY];
	stream_enabled[REC] = !!mmap_map[REC];

	return 0;
}

static ssize_t padsp_munmap(enum ossp_opcode opcode,
			    void *carg, void *din, size_t din_sz,
			    void *rarg, void *dout, size_t *dout_szp, int tfd)
{
	int dir = *(int *)carg;

	assert(mmap_map[dir]);
	kill_streams();
	mmap_map[dir] = NULL;
	return 0;
}

static ssize_t padsp_flush(enum ossp_opcode opcode,
			   void *carg, void *din, size_t din_sz,
			   void *rarg, void *dout, size_t *dout_szp, int tfd)
{
	flush_streams(opcode == OSSP_DSP_SYNC);
	return 0;
}

static ssize_t padsp_post(enum ossp_opcode opcode,
			  void *carg, void *din, size_t din_sz,
			  void *rarg, void *dout, size_t *dout_szp, int tfd)
{
	return trigger_streams(1, -1);
}

static ssize_t padsp_get_param(enum ossp_opcode opcode,
			       void *carg, void *din, size_t din_sz,
			       void *rarg, void *dout, size_t *dout_szp,
			       int tfd)
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
		v = user_frag_size;
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
			       void *rarg, void *dout, size_t *dout_szp,
			       int tfd)
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
			v = user_subdivision ?: 1;
			break;
		}
		user_frag_size= 0;
		user_subdivision = v;
		break;

	case OSSP_DSP_SET_FRAGMENT:
		user_subdivision = 0;
		user_frag_size = 1 << (v & 0xffff);
		user_max_frags = (v >> 16) & 0xffff;
		if (user_frag_size < 4)
			user_frag_size = 4;
		if (user_max_frags < 2)
			user_max_frags = 2;
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
				 void *rarg, void *dout, size_t *dout_szp,
				 int fd)
{
	int enable = *(int *)carg;

	return trigger_streams(enable & PCM_ENABLE_OUTPUT,
			       enable & PCM_ENABLE_INPUT);
}

static ssize_t padsp_get_space(enum ossp_opcode opcode,
			       void *carg, void *din, size_t din_sz,
			       void *rarg, void *dout, size_t *dout_szp, int tfd)
{
	int dir = (opcode == OSSP_DSP_GET_OSPACE) ? PLAY : REC;
	struct audio_buf_info info = { };
	int rc;

	rc = prepare_streams();
	if (rc)
		return -EIO;

	if (mmapped()) {
		info.fragments = mmap_raw_size / user_frag_size;
		info.fragstotal = info.fragments;
		info.fragsize = user_frag_size;
		info.bytes = mmap_raw_size;
	} else {
		size_t space;

		if (dir == PLAY)
			space = pa_stream_writable_size(stream[PLAY]);
		else
			space = pa_stream_readable_size(stream[REC]);

		space = round_down(space, user_frag_size);
		space = min(space, user_frag_size * user_max_frags);

		info.fragments = space / user_frag_size;
		info.fragstotal = user_max_frags;
		info.fragsize = user_frag_size;
		info.bytes = space;
	}

	*(struct audio_buf_info *)rarg = info;
	return 0;
}

static ssize_t padsp_get_ptr(enum ossp_opcode opcode,
			     void *carg, void *din, size_t din_sz,
			     void *rarg, void *dout, size_t *dout_szp, int tfd)
{
	int dir = (opcode == OSSP_DSP_GET_OPTR) ? PLAY : REC;
	struct count_info info = { };

	if (prepare_streams() < 0 || !stream[dir])
		return -EIO;

	if (mmap_map[dir]) {
		/* mmap operation in progress, report mmap buffer parameters */
		if (dir == PLAY)
			mmap_fill_pstg();
		else
			mmap_consume_rstg();

		info.bytes = mmap_idx[dir];
		info.blocks = (mmap_idx[dir] - mmap_last_idx[dir]) / frame_size;
		info.ptr = mmap_idx[dir] % mmap_size;

		mmap_last_idx[dir] = mmap_idx[dir];
	} else {
		/* simulate pointers using timestamps */
		double bpus = (double)sample_bps / 1000000;
		size_t bytes, delta_bytes;
		pa_usec_t usec, delta;

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
		info.ptr = bytes % user_max_length;
	}

	*(struct count_info *)rarg = info;
	return 0;
}

static ssize_t padsp_get_odelay(enum ossp_opcode opcode,
				void *carg, void *din, size_t din_sz,
				void *rarg, void *dout, size_t *dout_szp,
				int fd)
{
	double bpus = (double)sample_bps / 1000000;
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
	[OSSP_DSP_MMAP]		= padsp_mmap,
	[OSSP_DSP_MUNMAP]	= padsp_munmap,
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
	int rc;

	ossp_slave_init(argc, argv);

	page_size = sysconf(_SC_PAGE_SIZE);

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
		rc = ossp_slave_process_command(ossp_cmd_fd, action_fn_tbl,
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
