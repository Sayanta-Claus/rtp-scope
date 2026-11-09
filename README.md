# rtp-scope

[![CI](https://github.com/Sayanta-Claus/rtp-scope/actions/workflows/ci.yml/badge.svg)](https://github.com/Sayanta-Claus/rtp-scope/actions/workflows/ci.yml)

A zero-dependency C++17 RTP analyzer, traffic generator and jitter-buffer simulator.

_Work in progress: the full README (design, results, limitations) is written in milestone 6._

## Build

```
cmake -S . -B build && cmake --build build -j && ctest --test-dir build --output-on-failure
cmake -S . -B build-san -DSANITIZE=ON -DCMAKE_BUILD_TYPE=Debug   # ASan + UBSan
```
