CMAKE_MINIMUM_REQUIRED(VERSION 2.8)
project("netflows" C)

# for more verbose output set CTEST_OUTPUT_ON_FAILURE in environment
# or run tests by calling ctest with --output-on-failure
enable_testing()

find_package(Check REQUIRED)
include_directories(${CHECK_INCLUDE_DIRS})

# just call build_check_tests() to generate tests for current source dir
# may be called with additional source files as parameter
set(PROJECT_LINK_DEPENDENCIES pcap)
macro (build_check_tests)

	file(GLOB_RECURSE TESTFILES "${CMAKE_CURRENT_SOURCE_DIR}" "*.check")

	foreach(TESTFILE ${TESTFILES})
		get_filename_component(file_name ${TESTFILE} NAME_WE)
		set(source_file_name ${file_name}.c)
		execute_process(COMMAND touch ${CMAKE_CURRENT_BINARY_DIR}/${source_file_name})
		execute_process(COMMAND sh -c "cat ${TESTFILE} | checkmk > ${CMAKE_CURRENT_BINARY_DIR}/${source_file_name}")
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
