// test_mutation.cpp -- robustness: damaged captures must never crash or hang.
//
// What it does:
//   Builds a few valid captures (different link layers, byte orders, loss,
//   duplicates, plus hand-made odd packets: RTCP, padding, extensions, CSRCs,
//   fragments, non-RTP UDP), then analyses thousands of corrupted copies with
//   fixed seeds. Every run goes through the full path: Analyzer, text and JSON
//   reports, trace extraction and both jitter-buffer simulations.
//
// What "pass" means: no crash, no sanitizer report (the build in CI/ctest uses
// ASan+UBSan with -fno-sanitize-recover, so any finding aborts the test), no
// uncaught exception, no case slower than 5 s, and the counter invariant (every
// frame lands in exactly one bucket). The analysis may succeed or reject the
// file with an error message; both are fine.
//
// Summary line (captured into results/robustness.txt by scripts/fuzz.sh):
//   mutations=N analysed_ok=A rejected_cleanly=R ...
#include <chrono>
#include <cstdio>
#include <sstream>

#include "mutator.hpp"
#include "report.hpp"
#include "test_harness.hpp"
#include "test_support.hpp"
#include "trace_gen.hpp"

using namespace rtpscope;

namespace {

constexpr uint64_t kMutations = 3000;

std::vector<uint8_t> to_bytes(const std::string& s) { return std::vector<uint8_t>(s.begin(), s.end()); }

std::vector<uint8_t> generated(const GenConfig& c) {
    std::vector<GeneratedPacket> arr;
    GroundTruth t;
    generate_trace(c, arr, t);
    std::ostringstream os(std::ios::binary);
    write_trace_pcap(c, arr, os);
    return to_bytes(os.str());
}

// A capture full of unusual-but-valid packets.
std::vector<uint8_t> odd_packets() {
    using support::make_pcap;
    std::vector<std::pair<uint64_t, std::vector<uint8_t>>> f;
    FrameSpec fs;
    uint64_t t = 0;
    auto add = [&](const std::vector<uint8_t>& udp_payload, const FrameSpec& spec = FrameSpec()) {
        f.emplace_back(t += 20000000, build_udp_frame(spec, udp_payload));
    };
    for (uint16_t s = 0; s < 20; ++s) {
        RtpPacketSpec r;
        r.sequence = static_cast<uint16_t>(65530 + s);
        r.timestamp = s * 160u;
        r.ssrc = 0xabcdef01;
        r.csrcs = {1, 2, 3};
        r.extension = s % 2 == 0;
        r.extension_words = 2;
        r.padding_bytes = s % 3 == 0 ? 8 : 0;
        r.marker = s % 5 == 0;
        add(build_rtp_packet(r));
    }
    add({0x80, 200, 0, 6, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0});  // RTCP SR
    add({0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0});                        // DNS-ish UDP
    FrameSpec vlan;
    vlan.vlan = true;
    RtpPacketSpec v;
    v.ssrc = 7;
    add(build_rtp_packet(v), vlan);
    auto frag = build_udp_frame(fs, build_rtp_packet(v));
    frag[14 + 6] = 0x20;
    f.emplace_back(t += 20000000, frag);
    return to_bytes(make_pcap(f));
}

struct Outcome {
    bool accepted = false;
};

Outcome analyse_everything(const std::vector<uint8_t>& bytes) {
    std::istringstream in(std::string(bytes.begin(), bytes.end()), std::ios::binary);
    Analyzer a(ClockRates(), /*keep_arrivals=*/true);
    std::string err;
    Outcome o;
    o.accepted = a.analyze(in, err);
    if (!o.accepted) {
        CHECK(!err.empty());  // a rejection must explain itself
        return o;
    }
    const Counters& c = a.counters();
    CHECK_EQ(c.rtp + c.rtcp + c.non_rtp_udp + c.non_ipv4 + c.non_udp + c.fragments + c.malformed(), c.frames);

    std::ostringstream text, json;
    print_text(text, "mutant.pcap", a);
    print_json(json, "mutant.pcap", a);
    for (const auto& s : a.streams()) {
        CHECK(s->lost() <= s->expected());
        const PlayoutTrace trace = make_trace(*s);
        const SimResult fixed = simulate_fixed(trace, 60);
        const SimResult adaptive = simulate_adaptive(trace, AdaptiveParams());
        CHECK(fixed.late_or_lost_percent >= 0.0 && adaptive.late_or_lost_percent >= 0.0);
        (void)sweep_csv(trace, AdaptiveParams());
    }
    return o;
}

}  // namespace

TEST(corpus_files_are_valid_before_mutation) {
    std::vector<std::vector<uint8_t>> corpus;
    GenConfig a;
    a.packets = 150;
    a.loss = 0.1;
    a.duplicate = 0.1;
    a.reorder = 0.1;
    a.jitter_ms = 15;
    a.start_seq = 65480;
    corpus.push_back(generated(a));
    for (const auto& bytes : corpus) CHECK(analyse_everything(bytes).accepted);
    CHECK(analyse_everything(odd_packets()).accepted);
}

TEST(mutated_captures_never_crash_or_hang) {
    std::vector<std::vector<uint8_t>> corpus;
    GenConfig plain;
    plain.packets = 120;
    plain.loss = 0.1;
    plain.duplicate = 0.1;
    plain.reorder = 0.1;
    plain.jitter_ms = 15;
    plain.start_seq = 65480;
    corpus.push_back(generated(plain));
    GenConfig exotic = plain;
    exotic.seed = 2;
    exotic.vlan = true;
    exotic.nanosecond = true;
    exotic.big_endian = true;
    corpus.push_back(generated(exotic));
    GenConfig sll = plain;
    sll.seed = 3;
    sll.sll = true;
    sll.talk_on_ms = 300;
    sll.talk_off_ms = 200;
    corpus.push_back(generated(sll));
    corpus.push_back(odd_packets());

    uint64_t accepted = 0, rejected = 0;
    double slowest_ms = 0;
    for (uint64_t seed = 1; seed <= kMutations; ++seed) {
        const std::vector<uint8_t> mutant = fuzz::mutate(corpus[seed % corpus.size()], seed);
        const auto start = std::chrono::steady_clock::now();
        try {
            (analyse_everything(mutant).accepted ? accepted : rejected)++;
        } catch (const std::exception& e) {
            testing::fail(__FILE__, __LINE__, "exception for seed " + std::to_string(seed) + ": " + e.what());
        } catch (...) {
            testing::fail(__FILE__, __LINE__, "unknown exception for seed " + std::to_string(seed));
        }
        const double ms = std::chrono::duration<double, std::milli>(std::chrono::steady_clock::now() - start).count();
        if (ms > slowest_ms) slowest_ms = ms;
        CHECK(ms < 5000.0);
    }
    std::printf("mutations=%llu analysed_ok=%llu rejected_cleanly=%llu slowest_case_ms=%.1f\n",
                static_cast<unsigned long long>(kMutations), static_cast<unsigned long long>(accepted),
                static_cast<unsigned long long>(rejected), slowest_ms);
    CHECK_EQ(accepted + rejected, kMutations);
}

TEST_MAIN()
