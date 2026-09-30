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

if(MSVC)
    add_compile_options(
        $<$<CONFIG:Debug>:/Od>
        $<$<CONFIG:Debug>:/RTC1>
        $<$<CONFIG:Release>:/O2>)
else()
    add_compile_options(
        $<$<CONFIG:Release>:-O2>
        -march=native)
endif()

# ===== CONFIG PATH =====
get_filename_component(ABSOLUTE_CONFIG_PATH "${PROJECT_SOURCE_DIR}/config" ABSOLUTE)
add_compile_definitions(CONFIG_PATH="${ABSOLUTE_CONFIG_PATH}")


# ===== LOGGING =====
find_package(spdlog QUIET)
if (NOT spdlog_FOUND)
    message(FATAL_ERROR "spdlog not found. Install it: "
        "'sudo apt install libspdlog-dev' (Linux) or 'brew install spdlog' (macOS).")
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
)

target_include_directories(${ANALYSE_LOG_NAME} PUBLIC
    ${PROJECT_SOURCE_DIR}/include
)

if(MSVC)
    target_compile_options(${ANALYSE_LOG_NAME} PRIVATE /W4)
else()
    target_compile_options(${ANALYSE_LOG_NAME} PRIVATE -Wall -Wextra -Werror)
endif()

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
    )

    target_include_directories(unit_tests PUBLIC
        ${PROJECT_SOURCE_DIR}/include
        ${CRITERION_INCLUDE_DIRS}
    )
    target_link_libraries(unit_tests PRIVATE ${CRITERION_LIBRARIES} spdlog::spdlog)
    target_compile_options(unit_tests PRIVATE ${CRITERION_CFLAGS_OTHER})

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

if (WIN32)
    add_compile_definitions(_WINSOCK_DEPRECATED_NO_WARNINGS)
    target_link_libraries(${OUTPUT_NAME} PRIVATE ws2_32)
endif()
if (MSVC)
    add_compile_definitions(_CRT_SECURE_NO_WARNINGS)
    target_compile_definitions(${OUTPUT_NAME} PRIVATE NOMINMAX WIN32_LEAN_AND_MEAN)
    target_compile_options(${OUTPUT_NAME} PRIVATE /wd4200 /wd4244 /wd4267 /wd4458 /wd4275)
endif()

target_include_directories(${OUTPUT_NAME} PUBLIC
    ${PROJECT_SOURCE_DIR}/include
)

if(MSVC)
    target_compile_options(${OUTPUT_NAME} PRIVATE /W4)
else()
    target_compile_options(${OUTPUT_NAME} PRIVATE -Wall -Wextra -Werror)
endif()

if (WIN32)
    add_custom_command(TARGET ${OUTPUT_NAME} POST_BUILD
        COMMAND ${CMAKE_COMMAND} -E copy_if_different
            $<TARGET_RUNTIME_DLLS:${OUTPUT_NAME}>
            $<TARGET_FILE_DIR:${OUTPUT_NAME}>
        COMMAND_EXPAND_LISTS
    )
endif()
