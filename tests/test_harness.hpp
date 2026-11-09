// test_harness.hpp -- a ~40 line unit-test harness (no third-party framework).
//
// What it does:
//   TEST(name) { ... } registers a test function at static-init time; CHECK /
//   CHECK_EQ record failures with file:line instead of aborting, so one run
//   shows every failing assertion. TEST_MAIN() expands to a main() that runs
//   all registered tests and returns non-zero if any check failed (ctest then
//   marks the test failed).
//
// Where it sits: each tests/test_*.cpp includes this and links rtpscope_core.
//
// Design decision:
//   Tests must be easy to read in an interview, so the harness is tiny and
//   has no macros beyond the four below.
#pragma once

#include <cstdio>
#include <functional>
#include <sstream>
#include <string>
#include <utility>
#include <vector>

namespace testing {

struct State {
    std::vector<std::pair<std::string, std::function<void()>>> tests;
    int failures = 0;
    int checks = 0;
};

inline State& state() {
    static State s;
    return s;
}

struct Registrar {
    Registrar(const char* name, std::function<void()> fn) { state().tests.emplace_back(name, std::move(fn)); }
};

inline void fail(const char* file, int line, const std::string& message) {
    ++state().failures;
    std::fprintf(stderr, "  FAIL %s:%d: %s\n", file, line, message.c_str());
}

template <typename A, typename B>
void check_eq(const A& a, const B& b, const char* ea, const char* eb, const char* file, int line) {
    ++state().checks;
    if (!(a == b)) {
        std::ostringstream os;
        os << ea << " == " << eb << "  (got " << a << " vs " << b << ")";
        fail(file, line, os.str());
    }
}

inline int run_all() {
    for (auto& t : state().tests) {
        const int before = state().failures;
        t.second();
        std::printf("[%s] %s\n", state().failures == before ? " ok " : "FAIL", t.first.c_str());
    }
    std::printf("%d checks, %d failures\n", state().checks, state().failures);
    return state().failures == 0 ? 0 : 1;
}

}  // namespace testing

#define TEST(name)                                              \
    static void name();                                         \
    static ::testing::Registrar registrar_##name(#name, name);  \
    static void name()

#define CHECK(cond)                                                   \
    do {                                                              \
        ++::testing::state().checks;                                  \
        if (!(cond)) ::testing::fail(__FILE__, __LINE__, #cond);      \
    } while (0)

#define CHECK_EQ(a, b) ::testing::check_eq((a), (b), #a, #b, __FILE__, __LINE__)

#define TEST_MAIN() \
    int main() { return ::testing::run_all(); }
