// Tests for cpl::plugins — the ifw plugin contract (package parsing).
//
// Previously plugins.hpp had zero test coverage, which let the enum-migration
// regression (Error::FileOpen.i64 on an enum value) slip through to ifw. This
// file ensures the header's inline functions actually instantiate: we call
// ParseRuntimeConfig (pure JSON) and LoadPackageConfig (file open path) so the
// compiler must type-check every branch.
#include "../vendor/doctest/doctest.hpp"
#include "../plugins.hpp"

#include <string>
#include <vector>

using namespace cpl;
using namespace cpl::plugins;

TEST_SUITE("cpl::plugins config parsing") {
    TEST_CASE("ParseRuntimeConfig parses a well-formed config") {
        const auto cfg = ParseRuntimeConfig(R"({
            "name": "demo",
            "description": "a demo plugin",
            "version": "1.0.0",
            "enabled": true,
            "run_mode": "repeat",
            "run_as": "system",
            "allow_parallel": false,
            "interval_seconds": 120
        })");
        REQUIRE(cfg.has_value());
        CHECK_EQ(cfg.value().name, std::string("demo"));
        CHECK_EQ(cfg.value().version, std::string("1.0.0"));
        CHECK(cfg.value().enabled);
        CHECK_EQ(cfg.value().intervalSeconds, 120u);
    }

    TEST_CASE("ParseRuntimeConfig applies defaults for missing fields") {
        const auto cfg = ParseRuntimeConfig("{}");
        REQUIRE(cfg.has_value());
        CHECK_EQ(cfg.value().name, std::string(""));
        CHECK(cfg.value().enabled); // default true
        CHECK_EQ(cfg.value().intervalSeconds, 300u); // default
    }

    TEST_CASE("ParseRuntimeConfig rejects malformed json") {
        const auto cfg = ParseRuntimeConfig("{not json");
        CHECK_FALSE(cfg.has_value());
    }

    TEST_CASE("ParseRunMode / ParseRunAs / ParseFailureAction round-trip") {
        CHECK(ParseRunMode("repeat") == RunMode::Repeat);
        CHECK(ParseRunMode("once") == RunMode::Once);
        CHECK(ParseRunMode("unknown") == RunMode::Repeat); // default

        CHECK(ParseRunAs("system") == RunAs::System);
        CHECK(ParseRunAs("active_user") == RunAs::ActiveUser);

        CHECK(ParseFailureAction("log") == FailureAction::Log);
        CHECK(ParseFailureAction("disable") == FailureAction::Disable);
    }
}

TEST_SUITE("cpl::plugins package loading") {
    // A throwaway CA public key (32 bytes of zeros) — we only exercise the
    // file-open error path, no signature verification happens here.
    static const uint8_t kDummyCaKey[32] = {0};

    TEST_CASE("LoadPackageConfig rejects a missing file") {
        // This call must instantiate the fopen branch (plugins.hpp:317/322),
        // which previously held the enum regression Error::FileOpen.i64.
        const auto pkg = LoadPackageConfig("Z:/no/such/cpl_plugin_test.pkg",
                                           kDummyCaKey, sizeof(kDummyCaKey));
        CHECK_FALSE(pkg.has_value());
    }
}
