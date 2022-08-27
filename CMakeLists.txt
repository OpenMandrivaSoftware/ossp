cmake_minimum_required(VERSION 3.1)

list(APPEND CMAKE_MODULE_PATH
	"${CMAKE_CURRENT_SOURCE_DIR}/cmake"
)

project("OSS Proxy"
	VERSION 1.3.2
	DESCRIPTION "Emulate OSS device(s) using CUSE."
	HOMEPAGE_URL "https://github.com/OpenMandrivaSoftware/ossp"
	LANGUAGES "C"
)

option(alsa       "Build ALSA slave."       OFF)
option(daemon     "Build daemon."           ON)
option(pulseaudio "Build PulseAudio slave." ON)
option(test       "Build test."             OFF)

include(ossp-util)

if(test)
	include(CTest)
endif()

# Shared library
add_library(libossp OBJECT
	"ossp.c"
	"ossp.h"
	"ossp-slave.c"
	"ossp-slave.h"
	"ossp-util.c"
	"ossp-util.h"
)

# Daemon
if(daemon)
	add_executable(osspd "osspd.c")
	set_output_dir(osspd)

	link_pkg(osspd "fuse")
	target_link_libraries(osspd PRIVATE libossp)

	install_daemon(osspd)
endif()

# ALSA slave
if(alsa)
	add_executable(ossp-alsap "ossp-alsap.c")
	set_output_dir(ossp-alsap)

	link_pkg(ossp-alsap "alsa")
	target_link_libraries(ossp-alsap PRIVATE libossp)

	install_slave(ossp-alsap)
endif()

# PulseAudio slave
if(pulseaudio)
	add_executable(ossp-padsp "ossp-padsp.c")
	set_output_dir(ossp-padsp)

	link_pkg(ossp-padsp "libpulse")
	target_link_libraries(ossp-padsp PRIVATE libossp)

	install_slave(ossp-padsp)
endif()

if(test)
	add_executable(osstest "osstest.c")

	add_test(
		NAME osstest
		COMMAND osstest
		WORKING_DIRECTORY ${PROJECT_BINARY_DIR}
	)
endif()

install_udev_rules("98-osscuse.rules")
