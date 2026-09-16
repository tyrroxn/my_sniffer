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


# ===== SOURCES =====
if (APPLE)
    set(PLATFORM_CAPTURE_SOURCE ${PROJECT_SOURCE_DIR}/src/MacCapture.cpp)
elseif (CMAKE_SYSTEM_NAME STREQUAL "Linux")
    set(PLATFORM_CAPTURE_SOURCE ${PROJECT_SOURCE_DIR}/src/LinuxCapture.cpp)
else()
    message(FATAL_ERROR "No capture backend implemented for this platform")
endif()

add_executable(${OUTPUT_NAME}
    ${PROJECT_SOURCE_DIR}/src/main.cpp
    ${PROJECT_SOURCE_DIR}/src/Helper.cpp
    ${PROJECT_SOURCE_DIR}/src/SignalHandler.cpp
    ${PROJECT_SOURCE_DIR}/src/EthernetParser.cpp
    ${PROJECT_SOURCE_DIR}/src/Ipv4Parser.cpp
    ${PROJECT_SOURCE_DIR}/src/TcpParser.cpp
    ${PROJECT_SOURCE_DIR}/src/UdpParser.cpp
    ${PLATFORM_CAPTURE_SOURCE}
)

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
        ${PROJECT_SOURCE_DIR}/src/Helper.cpp
        ${PROJECT_SOURCE_DIR}/src/EthernetParser.cpp
        ${PROJECT_SOURCE_DIR}/src/Ipv4Parser.cpp
        ${PROJECT_SOURCE_DIR}/src/TcpParser.cpp
        ${PROJECT_SOURCE_DIR}/src/UdpParser.cpp
    )

    target_include_directories(unit_tests PUBLIC
        ${PROJECT_SOURCE_DIR}/include
        ${CRITERION_INCLUDE_DIRS}
    )
    target_link_libraries(unit_tests PRIVATE ${CRITERION_LIBRARIES})
    target_compile_options(unit_tests PRIVATE ${CRITERION_CFLAGS_OTHER})

    add_test(NAME unit_tests COMMAND unit_tests)

    add_custom_target(run_tests
        COMMAND unit_tests
        DEPENDS unit_tests
        WORKING_DIRECTORY ${CMAKE_BINARY_DIR}
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
