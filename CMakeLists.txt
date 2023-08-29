cmake_minimum_required(VERSION 3.7)
project(hellothere VERSION 1.0.0 LANGUAGES C)

include(FindPkgConfig)
pkg_search_module(GDK REQUIRED gdk-pixbuf-2.0)
pkg_search_module(GLIB REQUIRED glib-2.0)

set(CMAKE_THREAD_PREFER_PTHREAD TRUE)
set(THREADS_PREFER_PTHREAD_FLAG TRUE)
find_package(Threads REQUIRED)

add_executable(hellothere src/main.c)

include_directories(${GDK_INCLUDE_DIRS} ${GLIB_INCLUDE_DIRS})
target_link_libraries(hellothere ${GDK_LIBRARIES} ${GLIB_LIBRARIES} notify audit auparse Threads::Threads)

target_compile_options(hellothere PRIVATE -Werror -Wall -Wpedantic)
