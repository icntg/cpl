// Tests for cpl::win32::thread::Thread (Start / StartEx / handle accessors).
//
// Covers the win32 header previously not exercised by any test — this is the
// file whose phantom ../../ccl-del include slipped through to ifw. Thread
// creation is fully runtime-testable: we spin a worker, wait on its handle, and
// assert the side-effect ran.
#include "../vendor/doctest/doctest.hpp"
#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include "../win32/thread.hpp"

#include <atomic>
#include <chrono>
#include <thread>

using namespace cpl::win32::thread;

namespace {
// Shared counter incremented by the worker thread.
static std::atomic<int> g_counter{0};

// _beginthreadex/CreateThread callback signature: DWORD (*)(LPVOID).
static DWORD CALLBACK IncrementCounter(LPVOID) {
    g_counter.fetch_add(1);
    return 0;
}
} // namespace

TEST_SUITE("win32 thread::Thread") {
    TEST_CASE("Start runs the callback via CreateThread") {
        const int before = g_counter.load();
        {
            Thread t(IncrementCounter);
            t.Start();
            CHECK_NE(t.GetThreadId(), 0u);

            HANDLE h = t.GetThreadHandle();
            REQUIRE(h != nullptr);
            REQUIRE(h != INVALID_HANDLE_VALUE);
            // Wait for the worker to finish (it just increments).
            WaitForSingleObject(h, 5000);

            CHECK_GT(g_counter.load(), before);
        }
        // Thread destructor closes the handle.
    }

    TEST_CASE("StartEx runs the callback via _beginthreadex") {
        const int before = g_counter.load();
        {
            Thread t(IncrementCounter);
            t.StartEx();
            CHECK_NE(t.GetThreadId(), 0u);

            HANDLE h = t.GetThreadHandle();
            REQUIRE(h != nullptr);
            REQUIRE(h != INVALID_HANDLE_VALUE);
            WaitForSingleObject(h, 5000);

            CHECK_GT(g_counter.load(), before);
        }
    }

    TEST_CASE("thread handle is valid after start") {
        Thread t(IncrementCounter);
        t.Start();
        // Handle must be usable for synchronization.
        HANDLE h = t.GetThreadHandle();
        CHECK(h != nullptr);
        CHECK(h != INVALID_HANDLE_VALUE);
        WaitForSingleObject(h, 5000);
    }
}
