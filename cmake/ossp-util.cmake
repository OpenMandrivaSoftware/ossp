include(GNUInstallDirs)

find_package(PkgConfig REQUIRED)

set(INSTALL_UDEVRULESDIR
	"${CMAKE_INSTALL_PREFIX}/lib/udev/rules.d"
	CACHE PATH
	"Install path for udev rules."
)

function(link_pkg TARGET PKG)
	pkg_search_module(${PKG} ${PKG} REQUIRED)

	target_compile_options(${TARGET} PRIVATE ${${PKG}_CFLAGS})
	target_include_directories(${TARGET} PRIVATE ${${PKG}_INCLUDE_DIRS})
	target_link_libraries(${TARGET} PRIVATE ${${PKG}_LINK_LIBRARIES})
endfunction()

macro(set_output_dir TARGET)
	set_target_properties(${TARGET}
		PROPERTIES
			RUNTIME_OUTPUT_DIRECTORY ${PROJECT_BINARY_DIR}
	)
endmacro()

macro(install_daemon TARGET)
	install(TARGETS ${TARGET}
		RUNTIME DESTINATION ${CMAKE_INSTALL_SBINDIR}
	)
endmacro()

macro(install_slave TARGET)
	install(TARGETS ${TARGET}
		RUNTIME DESTINATION "${CMAKE_INSTALL_LIBEXECDIR}/ossp"
	)
endmacro()

macro(install_udev_rules FILES)
	install(FILES ${FILES}
		DESTINATION ${INSTALL_UDEVRULESDIR}
	)
endmacro()
