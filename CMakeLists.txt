CMAKE_MINIMUM_REQUIRED(VERSION 2.8)
project("netflows" C)

# for more verbose output set CTEST_OUTPUT_ON_FAILURE in environment
# or run tests by calling ctest with --output-on-failure
enable_testing()

# ugly workaround - there is no recent check package in ubuntu 12.04
# (package not found - even if installed)
find_package(Check QUIET)
if (CHECK_FOUND)
	include_directories(${CHECK_INCLUDE_DIRS})
	set(CHECKMK_TOOL checkmk)
else()
	message("***going to use build-in checkmk tool***")
	set(CHECKMK_TOOL ${PROJECT_SOURCE_DIR}/contrib/check/checkmk)
endif()

# just call build_check_tests() to generate tests for current source dir
# may be called with additional source files as parameter
# TODO: dpk-config --libs ... could solve this problem
execute_process(COMMAND sh -c "lsb_release -r | grep 14.04 | wc -l" OUTPUT_VARIABLE IS_UBUNTU_14.04)
if ( 1 EQUAL ${IS_UBUNTU_14.04})
	set(PROJECT_LINK_DEPENDENCIES pcap cap gcrypt rt pthread curl m ncurses libndpi nfnetlink netfilter_queue libjansson ${GENERATED_LIBS})
else()
	set(PROJECT_LINK_DEPENDENCIES usb-1.0 pcap cap gcrypt rt dbus-1 pthread curl m ncurses libndpi nfnetlink netfilter_queue libjansson ${GENERATED_LIBS})
endif()
macro (build_check_tests)

	file(GLOB_RECURSE TESTFILES "${CMAKE_CURRENT_SOURCE_DIR}" "*.check")

	foreach(TESTFILE ${TESTFILES})
		get_filename_component(file_name ${TESTFILE} NAME_WE)
		set(source_file_name ${file_name}.c)
		execute_process(COMMAND touch ${CMAKE_CURRENT_BINARY_DIR}/${source_file_name})
		execute_process(COMMAND sh -c "cat ${TESTFILE} | ${CHECKMK_TOOL} > ${CMAKE_CURRENT_BINARY_DIR}/${source_file_name}")
		set(ADD_SRC_FILES)
		if (${ARGC} GREATER 0 )
			foreach (ADD_SOURCE ${ARGV})
				list(APPEND ADD_SRC_FILES ${ADD_SOURCE})
			endforeach()
		endif()
		add_executable(${file_name} ${CMAKE_CURRENT_BINARY_DIR}/${source_file_name} ${ADD_SRC_FILES})
		target_link_libraries(${file_name} check ${PROJECT_LINK_DEPENDENCIES})
		add_test(${file_name} ${file_name})
	endforeach()

endmacro ()

add_subdirectory(packetprocessor)
add_subdirectory(utils/pcap-generator)
