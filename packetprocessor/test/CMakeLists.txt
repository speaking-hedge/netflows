set(PCAP_SOURCE_DIR ${PROJECT_SOURCE_DIR}/pcaps)
set(PCAP_TARGET_DIR testcaps)

file(COPY ${PCAP_SOURCE_DIR}/small.pcap DESTINATION ${CMAKE_CURRENT_BINARY_DIR}/${PCAP_TARGET_DIR}/)
file(COPY ${PCAP_SOURCE_DIR}/small.pcapng DESTINATION ${CMAKE_CURRENT_BINARY_DIR}/${PCAP_TARGET_DIR}/)
file(COPY ${PCAP_SOURCE_DIR}/corrupted.pcap DESTINATION ${CMAKE_CURRENT_BINARY_DIR}/${PCAP_TARGET_DIR}/)
execute_process(
	COMMAND sh -c "echo 'just some text' > ${CMAKE_CURRENT_BINARY_DIR}/${PCAP_TARGET_DIR}/iamtext"
)

INCLUDE_DIRECTORIES(${PROJECT_SOURCE_DIR}/packetprocessor)

build_check_tests("${CMAKE_CURRENT_SOURCE_DIR}/../pp_fnct.c" "${CMAKE_CURRENT_SOURCE_DIR}/../libc_wrapper.c" "${CMAKE_CURRENT_SOURCE_DIR}/../pp_flow.c" "${CMAKE_CURRENT_SOURCE_DIR}/../pp_analyzer.c" "${CMAKE_CURRENT_SOURCE_DIR}/../pp_ndpi.c" "${CMAKE_CURRENT_SOURCE_DIR}/../pp_flowtop.c" "${CMAKE_CURRENT_SOURCE_DIR}/../pp_decap.c")

add_custom_command(OUTPUT ${PROJECT_BINARY_DIR}/packetprocessor/test/testcaps/testfile.pcap
	DEPENDS generate
	COMMAND ${PROJECT_BINARY_DIR}/utils/pcap-generator/generate testfile.pcap
	COMMAND mv testfile.pcap ${PROJECT_BINARY_DIR}/packetprocessor/test/testcaps/testfile.pcap
)

add_custom_target(gentestcaps ALL DEPENDS ${PROJECT_BINARY_DIR}/packetprocessor/test/testcaps/testfile.pcap)
