# ===== SETUP =====
cmake_minimum_required(VERSION 3.16)
cmake_policy(SET CMP0048 NEW)

project(My_sniffer
    VERSION 1.0.0
    DESCRIPTION "My_sniffer"
    HOMEPAGE_URL "https://github.com/tyrroxn/my_sniffer.git"
    LANGUAGES CXX
)

set(COMPAT_VERSION 1.0.0)
set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

set(OUTPUT_NAME my_sniffer)
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}")

# ===== OPTIONS =====
if ("${CMAKE_BUILD_TYPE}" STREQUAL "Debug")
    add_compile_definitions(DEBUG)
endif()

add_compile_options($<$<CONFIG:Release>:-O2>)

# ===== CONFIG PATH =====
get_filename_component(ABSOLUTE_CONFIG_PATH "${PROJECT_SOURCE_DIR}/config" ABSOLUTE)
add_compile_definitions(CONFIG_PATH="${ABSOLUTE_CONFIG_PATH}")


# ===== LOGGING =====
find_package(spdlog QUIET)
if (NOT spdlog_FOUND)
    message(STATUS "spdlog not found on this system: downloading spdlog 1.15.3")
    include(FetchContent)
    if (POLICY CMP0135)
        cmake_policy(SET CMP0135 NEW)
    endif()
    FetchContent_Declare(spdlog
        URL https://github.com/gabime/spdlog/archive/refs/tags/v1.15.3.tar.gz
        URL_HASH SHA256=15a04e69c222eb6c01094b5c7ff8a249b36bb22788d72519646fb85feb267e67
    )
    FetchContent_MakeAvailable(spdlog)
    get_target_property(SPDLOG_INCLUDE_DIRS spdlog INTERFACE_INCLUDE_DIRECTORIES)
    set_target_properties(spdlog PROPERTIES INTERFACE_SYSTEM_INCLUDE_DIRECTORIES "${SPDLOG_INCLUDE_DIRS}")
endif()

# ===== SOURCES =====
if (APPLE)
    set(PLATFORM_CAPTURE_SOURCE ${PROJECT_SOURCE_DIR}/src/capture/MacCapture.cpp)
elseif (CMAKE_SYSTEM_NAME STREQUAL "Linux")
    set(PLATFORM_CAPTURE_SOURCE ${PROJECT_SOURCE_DIR}/src/capture/LinuxCapture.cpp)
else()
    message(FATAL_ERROR "No capture backend implemented for this platform")
endif()

add_executable(${OUTPUT_NAME}
    ${PROJECT_SOURCE_DIR}/src/main.cpp
    ${PROJECT_SOURCE_DIR}/src/utils/Helper.cpp
    ${PROJECT_SOURCE_DIR}/src/utils/SignalHandler.cpp
    ${PROJECT_SOURCE_DIR}/src/parsers/EthernetParser.cpp
    ${PROJECT_SOURCE_DIR}/src/parsers/Ipv4Parser.cpp
    ${PROJECT_SOURCE_DIR}/src/parsers/TcpParser.cpp
    ${PROJECT_SOURCE_DIR}/src/parsers/UdpParser.cpp
    ${PROJECT_SOURCE_DIR}/src/cli/PacketDisplay.cpp
    ${PROJECT_SOURCE_DIR}/src/cli/PacketFilter.cpp
    ${PROJECT_SOURCE_DIR}/src/cli/TerminalInput.cpp
    ${PROJECT_SOURCE_DIR}/src/log/Logger.cpp
    ${PLATFORM_CAPTURE_SOURCE}
)

target_link_libraries(${OUTPUT_NAME} PRIVATE spdlog::spdlog)

set(ANALYSE_LOG_NAME analyse_log)

add_executable(${ANALYSE_LOG_NAME}
    ${PROJECT_SOURCE_DIR}/src/anlyse_log_main.cpp
    ${PROJECT_SOURCE_DIR}/src/analysis/LogParser.cpp
    ${PROJECT_SOURCE_DIR}/src/analysis/SpikeServicesDetector.cpp
    ${PROJECT_SOURCE_DIR}/src/analysis/SpikeNetworkDetector.cpp
    ${PROJECT_SOURCE_DIR}/src/analysis/BeaconDetector.cpp
    ${PROJECT_SOURCE_DIR}/src/analysis/IpWhitelist.cpp
    ${PROJECT_SOURCE_DIR}/src/analysis/ForeignIpDetector.cpp
    ${PROJECT_SOURCE_DIR}/src/analysis/ProtocolDetector.cpp
    ${PROJECT_SOURCE_DIR}/src/analysis/Report.cpp
)

target_include_directories(${ANALYSE_LOG_NAME} PUBLIC
    ${PROJECT_SOURCE_DIR}/include
)

target_compile_options(${ANALYSE_LOG_NAME} PRIVATE -Wall -Wextra -Werror)

add_custom_target(re
    COMMAND ${CMAKE_COMMAND} --build ${CMAKE_BINARY_DIR} --target clean
    COMMAND ${CMAKE_COMMAND} --build ${CMAKE_BINARY_DIR} --target ${OUTPUT_NAME}
    USES_TERMINAL
)

# ===== TESTS =====
find_package(PkgConfig QUIET)
if (PkgConfig_FOUND)
    pkg_check_modules(CRITERION QUIET criterion)
endif()

if (CRITERION_FOUND)
    enable_testing()

    add_executable(unit_tests
        ${PROJECT_SOURCE_DIR}/tests/test_Helper.cpp
        ${PROJECT_SOURCE_DIR}/tests/test_EthernetParser.cpp
        ${PROJECT_SOURCE_DIR}/tests/test_Ipv4Parser.cpp
        ${PROJECT_SOURCE_DIR}/tests/test_TcpParser.cpp
        ${PROJECT_SOURCE_DIR}/tests/test_UdpParser.cpp
        ${PROJECT_SOURCE_DIR}/tests/test_Logger.cpp
        ${PROJECT_SOURCE_DIR}/tests/test_PacketFilter.cpp
        ${PROJECT_SOURCE_DIR}/tests/test_LogParser.cpp
        ${PROJECT_SOURCE_DIR}/tests/test_SpikeServicesDetector.cpp
        ${PROJECT_SOURCE_DIR}/tests/test_SpikeNetworkDetector.cpp
        ${PROJECT_SOURCE_DIR}/tests/test_BeaconDetector.cpp
        ${PROJECT_SOURCE_DIR}/tests/test_IpWhitelist.cpp
        ${PROJECT_SOURCE_DIR}/tests/test_ForeignIpDetector.cpp
        ${PROJECT_SOURCE_DIR}/tests/test_ProtocolDetector.cpp
        ${PROJECT_SOURCE_DIR}/tests/test_Report.cpp
        ${PROJECT_SOURCE_DIR}/src/utils/Helper.cpp
        ${PROJECT_SOURCE_DIR}/src/parsers/EthernetParser.cpp
        ${PROJECT_SOURCE_DIR}/src/parsers/Ipv4Parser.cpp
        ${PROJECT_SOURCE_DIR}/src/parsers/TcpParser.cpp
        ${PROJECT_SOURCE_DIR}/src/parsers/UdpParser.cpp
        ${PROJECT_SOURCE_DIR}/src/log/Logger.cpp
        ${PROJECT_SOURCE_DIR}/src/cli/PacketFilter.cpp
        ${PROJECT_SOURCE_DIR}/src/analysis/LogParser.cpp
        ${PROJECT_SOURCE_DIR}/src/analysis/SpikeServicesDetector.cpp
        ${PROJECT_SOURCE_DIR}/src/analysis/SpikeNetworkDetector.cpp
        ${PROJECT_SOURCE_DIR}/src/analysis/BeaconDetector.cpp
        ${PROJECT_SOURCE_DIR}/src/analysis/IpWhitelist.cpp
        ${PROJECT_SOURCE_DIR}/src/analysis/ForeignIpDetector.cpp
        ${PROJECT_SOURCE_DIR}/src/analysis/ProtocolDetector.cpp
        ${PROJECT_SOURCE_DIR}/src/analysis/Report.cpp
    )

    target_include_directories(unit_tests PUBLIC
        ${PROJECT_SOURCE_DIR}/include
        ${CRITERION_INCLUDE_DIRS}
    )
    target_link_libraries(unit_tests PRIVATE ${CRITERION_LIBRARIES} spdlog::spdlog)
    target_compile_options(unit_tests PRIVATE ${CRITERION_CFLAGS_OTHER})
    target_compile_options(unit_tests PRIVATE -include cstdint)

    target_compile_options(unit_tests PRIVATE --coverage -O0 -g)
    target_link_options(unit_tests PRIVATE --coverage)

    add_test(NAME unit_tests COMMAND unit_tests)

    add_custom_target(run_tests
        COMMAND unit_tests
        DEPENDS unit_tests
        WORKING_DIRECTORY ${CMAKE_BINARY_DIR}
    )

    add_custom_target(coverage
        COMMAND unit_tests
        COMMAND ${CMAKE_COMMAND} -E make_directory ${CMAKE_BINARY_DIR}/coverage
        COMMAND gcovr --root ${PROJECT_SOURCE_DIR}
            --filter ${PROJECT_SOURCE_DIR}/src
            --filter ${PROJECT_SOURCE_DIR}/include
            --exclude '.*tests/.*'
            --print-summary
            --html-details ${CMAKE_BINARY_DIR}/coverage/index.html
        DEPENDS unit_tests
        WORKING_DIRECTORY ${CMAKE_BINARY_DIR}
        COMMENT "Running unit_tests and generating gcovr HTML coverage report"
    )
else()
    message(STATUS "Criterion not found, skipping unit_tests target")
endif()

target_include_directories(${OUTPUT_NAME} PUBLIC
    ${PROJECT_SOURCE_DIR}/include
)

target_compile_options(${OUTPUT_NAME} PRIVATE -Wall -Wextra -Werror)

# ===== INSTALL =====
set(CMAKE_INSTALL_PREFIX "${PROJECT_SOURCE_DIR}/release")
include(GNUInstallDirs)

install(TARGETS ${OUTPUT_NAME} ${ANALYSE_LOG_NAME}
    RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
)
install(FILES ${PROJECT_SOURCE_DIR}/config/whitelist.conf
    DESTINATION ${CMAKE_INSTALL_SYSCONFDIR}/${OUTPUT_NAME}
)
