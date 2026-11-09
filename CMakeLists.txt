cmake_minimum_required(VERSION 3.16)
project(rtp_scope VERSION 1.0.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

if(NOT CMAKE_BUILD_TYPE AND NOT CMAKE_CONFIGURATION_TYPES)
  set(CMAKE_BUILD_TYPE Release CACHE STRING "Build type" FORCE)
endif()

option(SANITIZE "Build with AddressSanitizer + UndefinedBehaviorSanitizer" OFF)

add_library(rtpscope_warnings INTERFACE)
target_compile_options(rtpscope_warnings INTERFACE -Wall -Wextra -Wpedantic -Werror)
if(SANITIZE)
  # -fno-sanitize-recover makes UBSan findings abort (non-zero exit) instead of
  # printing and carrying on, so ctest cannot miss them.
  target_compile_options(rtpscope_warnings INTERFACE
    -fsanitize=address,undefined -fno-sanitize-recover=all -fno-omit-frame-pointer)
  target_link_options(rtpscope_warnings INTERFACE -fsanitize=address,undefined)
endif()

set(CORE_SOURCES
  src/pcap_reader.cpp
  src/net_decode.cpp
  src/rtp_header.cpp
  src/classify.cpp
  src/analyzer.cpp
  src/seq_tracker.cpp
  src/jitter.cpp
  src/clock_rate.cpp
  src/cli_args.cpp
  src/stream_stats.cpp
  src/report.cpp
  src/pcap_writer.cpp
  src/traffic_model.cpp
  src/trace_gen.cpp
  src/jitter_buffer.cpp
)

add_library(rtpscope_core STATIC ${CORE_SOURCES})
target_include_directories(rtpscope_core PUBLIC src)
target_link_libraries(rtpscope_core PUBLIC rtpscope_warnings)

add_executable(rtp_scope tools/rtp_scope.cpp)
target_link_libraries(rtp_scope PRIVATE rtpscope_core)

add_executable(rtp_gen tools/rtp_gen.cpp)
target_link_libraries(rtp_gen PRIVATE rtpscope_core)

# ---- tests ----
enable_testing()
set(TEST_NAMES
  test_byte_reader
  test_pcap
  test_net_decode
  test_rtp
  test_seq
  test_jitter
  test_stats
  test_report
  test_traffic
  test_e2e
  test_jitter_buffer
)
foreach(t ${TEST_NAMES})
  add_executable(${t} tests/${t}.cpp)
  target_link_libraries(${t} PRIVATE rtpscope_core)
  add_test(NAME ${t} COMMAND ${t})
endforeach()
