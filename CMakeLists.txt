cmake_minimum_required(VERSION 3.15 FATAL_ERROR)

project(iccp LANGUAGES C)

list(PREPEND CMAKE_MODULE_PATH "${PROJECT_SOURCE_DIR}/cmake")
find_package(SpicyPlugin REQUIRED)
spicy_plugin_require_version("8.0.0")
spicy_require_version("1.14.0")

if(NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE "Release" CACHE STRING "")
endif()

add_subdirectory(analyzer)
