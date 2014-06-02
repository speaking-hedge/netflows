set(LIBPCAP_SRC libpcap-1.5.3)
set(NDPI_SRC nDPI)
set(JANSSON_SRC jansson)
EXECUTE_PROCESS(COMMAND sh -c "git describe --abbrev=6 --dirty --always | tr -d '\n'" OUTPUT_VARIABLE GIT_SHA)

# build libpcap.a if needed
include(ExternalProject)
EXTERNALPROJECT_ADD(libpcap.a
	URL ${PROJECT_SOURCE_DIR}/contrib/${LIBPCAP_SRC}/
	CONFIGURE_COMMAND ${PROJECT_SOURCE_DIR}/contrib/${LIBPCAP_SRC}/configure
	BUILD_COMMAND make libpcap.a
	INSTALL_COMMAND sh -c "cp libpcap.a ${CMAKE_CURRENT_BINARY_DIR}"
)
INCLUDE_DIRECTORIES(${PROJECT_SOURCE_DIR}/contrib/${LIBPCAP_SRC}/)

# build libndpi if needed
EXTERNALPROJECT_ADD(libndpi.a
	URL ${PROJECT_SOURCE_DIR}/contrib/${NDPI_SRC}/
	CONFIGURE_COMMAND ${PROJECT_SOURCE_DIR}/contrib/${NDPI_SRC}/configure
	BUILD_COMMAND make
	INSTALL_COMMAND sh -c "cp ${CMAKE_CURRENT_BINARY_DIR}/libndpi.a-prefix/src/libndpi.a-build/src/lib/.libs/libndpi.a ${CMAKE_CURRENT_BINARY_DIR}"
)
INCLUDE_DIRECTORIES(${PROJECT_SOURCE_DIR}/contrib/${NDPI_SRC}/src/include)

# build jansson if needed
EXTERNALPROJECT_ADD(jansson.a
	URL ${PROJECT_SOURCE_DIR}/contrib/${JANSSON_SRC}/
	CONFIGURE_COMMAND cmake -DJANSSON_BUILD_DOCS=OFF ${PROJECT_SOURCE_DIR}/contrib/${JANSSON_SRC}/
	BUILD_COMMAND make -C ${CMAKE_CURRENT_BINARY_DIR}/jansson.a-prefix/src/jansson.a-build/
	INSTALL_COMMAND sh -c "cp ${CMAKE_CURRENT_BINARY_DIR}/jansson.a-prefix/src/jansson.a-build/lib/libjansson.a ${CMAKE_CURRENT_BINARY_DIR}"
)
INCLUDE_DIRECTORIES(${CMAKE_CURRENT_BINARY_DIR}/jansson.a-prefix/src/jansson.a-build/include)

# build packet processor
INCLUDE_DIRECTORIES(${CMAKE_CURRENT_SOURCE_DIR}/)
SET(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -DPPSHA=\\\"${GIT_SHA}\\\" -DPPCOMMITS=${REPO_COMMIT_COUNT}")
ADD_EXECUTABLE (packet-processor-static pp.c libc_wrapper.c pp_fnct.c pp_decap.c pp_flow.c pp_rest.c pp_analyzer.c pp_flowtop.c pp_ndpi.c)
set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -Wl,--wrap=memcpy -static-libgcc")

# link in available analysers
file(GLOB sub-dir ${CMAKE_CURRENT_SOURCE_DIR}/analyser/*)
foreach(dir ${sub-dir})
    if(IS_DIRECTORY ${dir})
		# there is at least one header file in each subfolder
		INCLUDE_DIRECTORIES(${dir})
		file(GLOB analyser_source ${dir}/*.c)
		get_filename_component(analyser_name ${analyser_source} NAME_WE)
		ADD_LIBRARY(${analyser_name} STATIC ${analyser_source})
		TARGET_LINK_LIBRARIES(packet-processor-static ${analyser_name})
    endif()
endforeach()

# add libpcap
ADD_LIBRARY(pcap STATIC IMPORTED)
SET_TARGET_PROPERTIES(pcap PROPERTIES IMPORTED_LOCATION ${CMAKE_CURRENT_BINARY_DIR}/libpcap.a)
# add libndpi
ADD_LIBRARY(libndpi STATIC IMPORTED)
SET_TARGET_PROPERTIES(libndpi PROPERTIES IMPORTED_LOCATION ${CMAKE_CURRENT_BINARY_DIR}/libndpi.a)
# add jansson
ADD_LIBRARY(libjansson STATIC IMPORTED)
SET_TARGET_PROPERTIES(libjansson PROPERTIES IMPORTED_LOCATION ${CMAKE_CURRENT_BINARY_DIR}/libjansson.a)

TARGET_LINK_LIBRARIES(packet-processor-static ${PROJECT_LINK_DEPENDENCIES})

# trigger build if needed
ADD_DEPENDENCIES(packet-processor-static libpcap.a)
ADD_DEPENDENCIES(packet-processor-static libndpi.la)
ADD_DEPENDENCIES(packet-processor-static jansson.a)

add_subdirectory(test)
