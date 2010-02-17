/* Simple oss testsuite
 *
 * Copyright (C) 2009 Maarten Lankhorst <m.b.lankhorst@gmail.com>
 *
 * This file is released under the GPLv2.
 */

#include <sys/types.h>
#include <sys/soundcard.h>
#include <sys/stat.h>
#include <sys/ioctl.h>
#include <stdio.h>
#include <stdarg.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <poll.h>
#include <sys/mman.h>
#include <stdlib.h>

#define MIXERDEV "/dev/mixer"
#define DSPDEV "/dev/dsp"

/* Test macros */

static int errors, success;
static int report_success = 1;

#define ok(a, b, c...) do { \
	if (!(a)) { \
		fprintf(stderr, "%s@%d test failed (%s): " b "\n", __func__, __LINE__, #a, ##c); \
		++errors; \
	} else { \
		if (report_success) \
			printf("%s@%d test succeeded (%s)\n", __func__, __LINE__, #a); \
		++success; \
	} } while (0)

static int mixerfd, dspfd;

static int reopen(int blocking)
{
	close(dspfd);
	if (!blocking)
		blocking = O_NDELAY;
	else
		blocking = 0;
	dspfd = open(DSPDEV, O_RDWR|blocking);
	return dspfd;
}

static void test_ro(int fd)
{
	int ret;
	char buf[1024];
	struct audio_buf_info abi;
	memset(buf, 0, sizeof(buf));

	ret = read(fd, buf, sizeof(buf));
	ok(ret >= 0, "%s", strerror(errno));

	ret = write(fd, buf, sizeof(buf));
	ok(ret < 0, "read %d bytes", ret);

	ret = ioctl(fd, SNDCTL_DSP_GETISPACE, &abi);
	ok(ret >= 0, "%s", strerror(errno));

	ret = ioctl(fd, SNDCTL_DSP_GETOSPACE, &abi);
	ok(ret < 0, "%s", strerror(errno));
	if (ret < 0)
		ok(errno == EINVAL, "Invalid errno: %s", strerror(errno));
}

static void test_wo(int fd)
{
	int ret;
	char buf[1024];
	struct audio_buf_info abi;
	memset(buf, 0, sizeof(buf));

	ret = read(fd, buf, sizeof(buf));
	ok(ret < 0, "read %d bytes", ret);

	ret = write(fd, buf, sizeof(buf));
	ok(ret >= 0, "%s", strerror(errno));

	ret = ioctl(fd, SNDCTL_DSP_GETISPACE, &abi);
	ok(ret < 0, "%s", strerror(errno));
	if (ret < 0)
		ok(errno == EINVAL, "Invalid errno: %s", strerror(errno));

	ret = ioctl(fd, SNDCTL_DSP_GETOSPACE, &abi);
	ok(ret >= 0, "%s", strerror(errno));
}

static void test_rw(int fd)
{
	int ret;
	char buf[1024];
	struct audio_buf_info abi;
	memset(buf, 0, sizeof(buf));

	ret = read(fd, buf, sizeof(buf));
	ok(ret >= 0, "%s", strerror(errno));

	ret = write(fd, buf, sizeof(buf));
	ok(ret >= 0, "%s", strerror(errno));

	ret = ioctl(fd, SNDCTL_DSP_GETISPACE, &abi);
	ok(ret >= 0, "%s", strerror(errno));

	ret = ioctl(fd, SNDCTL_DSP_GETOSPACE, &abi);
	ok(ret >= 0, "%s", strerror(errno));
}

static void test_open(void)
{
	int ro_fd, rw_fd, wo_fd;

	mixerfd = open(MIXERDEV, O_RDONLY|O_NDELAY);
	ok(mixerfd >= 0, "%s", strerror(errno));


	/* In order to make this work it has to be serialized
	 * alsa's kernel emulation can only have device open once
	 * so do some specific smokescreen tests here
	 * and then open dsp for testing
	 */
	ro_fd = open(DSPDEV, O_RDONLY);
	ok(ro_fd >= 0, "%s", strerror(errno));

	if (ro_fd >= 0)
		test_ro(ro_fd);

	close(ro_fd);

	wo_fd = open(DSPDEV, O_WRONLY);
	ok(wo_fd >= 0, "%s", strerror(errno));

	if (wo_fd >= 0)
		test_wo(wo_fd);

	close(wo_fd);

	rw_fd = open(DSPDEV, O_RDWR);
	ok(rw_fd >= 0, "%s", strerror(errno));

	if (rw_fd >= 0)
		test_rw(rw_fd);

	dspfd = rw_fd;
}

static void test_mixer(void)
{
	int ret;
	struct mixer_info info;
	memset(&info, 0, sizeof(info));

	ret = ioctl(mixerfd, SOUND_MIXER_INFO, &info);
	ok(ret >= 0, "%s", strerror(errno));
	if (ret >= 0) {
		printf("Mixer id: %s\n", info.id);
		printf("Name: %s\n", info.name);
	}
}

static void test_trigger(int fd)
{
	int ret, i;

	ret = ioctl(fd, SNDCTL_DSP_GETTRIGGER, &i);
	ok(ret == 0, "Returned error %s", strerror(errno));
	ok(i == (PCM_ENABLE_INPUT|PCM_ENABLE_OUTPUT), "i is set to %d", i);

	i = 0;
	ret = ioctl(fd, SNDCTL_DSP_SETTRIGGER, &i);
	ok(ret == 0, "Returned error %s", strerror(errno));
	ok(i == 0,  "Wrong i returned");

	i = PCM_ENABLE_INPUT|PCM_ENABLE_OUTPUT;
	ret = ioctl(fd, SNDCTL_DSP_SETTRIGGER, &i);
	ok(ret == 0, "Returned error %s", strerror(errno));
	ok(i == (PCM_ENABLE_INPUT|PCM_ENABLE_OUTPUT), "i has value %d", i);

	ret = ioctl(fd, SNDCTL_DSP_POST, NULL);
	ok(ret == 0, "Returned error %s", strerror(errno));
}

static void test_mmap(int fd)
{
	char *area;
	int ret;
	char buf[24];

	area = mmap(NULL, 8192, PROT_READ|PROT_WRITE, MAP_SHARED, fd, 0);
	ok(area != MAP_FAILED, "Failed to map: %s\n", strerror(errno));

	if (area == MAP_FAILED)
		return;

	ret = write(fd, &buf, sizeof(buf));
	ok(ret == -1, "write after mmap returned %i\n", ret);
	if (ret == -1)
		ok(errno == ENXIO, "Error returned is %s\n", strerror(errno));

	munmap(area, 8192);
}

static void test_notify(int fd)
{
	struct audio_buf_info bi;
	char *bytes = NULL;
	int ret, written;
	struct pollfd pfd = { fd, POLLOUT };
	int rounds = 20;

	ioctl(fd, SNDCTL_DSP_GETOSPACE, &bi);

	bytes = calloc(1, bi.fragsize);
	written = 0;
	ok(0, "Fragsize: %i, bytes: %i\n", bi.fragsize, bi.bytes);
	while (written + bi.fragsize - 1 < bi.bytes)
	{
		ret = write(fd, bytes, bi.fragsize);
		ok(ret == bi.fragsize, "Returned: %i instead of %i\n",
		   ret, bi.fragsize);
		if (ret > 0)
			written += ret;
	};

	while (rounds--)
	{
		ret = poll(&pfd, 1, -1);
		ok(ret > 0, "Poll returned %i\n", ret);
		if (ret < 0)
			break;
		ret = write(fd, bytes, bi.fragsize);
		if (ret < 0) ret = -errno;
		ok(ret == bi.fragsize, "Returned: %i instead of %i\n",
		   ret, bi.fragsize);
	}
}

int main()
{
	test_open();
	if (mixerfd >= 0)
		test_mixer();

	if (reopen(1) >= 0)
		test_trigger(dspfd);

	if (reopen(0) >= 0)
		test_notify(dspfd);

	if (reopen(1) >= 0)
		test_mmap(dspfd);

	close(mixerfd);
	close(dspfd);
	printf("Tests: %d errors %d success\n", errors, success);
	return errors > 127 ? 127 : errors;
}

