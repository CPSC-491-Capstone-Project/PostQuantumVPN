#ifndef _PQVPN_TESTS_REPLAY_WINDOW_TESTS_HPP_
#define _PQVPN_TESTS_REPLAY_WINDOW_TESTS_HPP_

#include "test_utils.hpp"
#include "replay_window.hpp"

using core::session::ReplayWindow;

// ============================================================================
// Tests
// ============================================================================

// Sequential counters 1, 2, 3 ... are all accepted
bool ReplayWindowTest_Sequential_AllAccepted() {
    ReplayWindow w;
    for (std::uint64_t i = 0; i < 100; ++i) {
        if (!w.Check(i)) return test_helper("accepted_" + std::to_string(i), "rejected");
        w.Accept(i);
    }
    return test_helper("1", "1");
}

// Counter 0 accepted on first use, rejected on second
bool ReplayWindowTest_Zero_AcceptedThenRejected() {
    ReplayWindow w;
    if (!w.Check(0)) return test_helper("first check", "rejected");
    w.Accept(0);
    return test_helper("1", std::to_string(!w.Check(0)));
}

// Duplicate counter is rejected
bool ReplayWindowTest_Duplicate_Rejected() {
    ReplayWindow w;
    w.Accept(10);
    return test_helper("1", std::to_string(!w.Check(10)));
}

// Out-of-order within window: receive 5, 3, 4 — all accepted; 3 again rejected
bool ReplayWindowTest_OutOfOrder_Accepted() {
    ReplayWindow w;

    if (!w.Check(5)) return test_helper("check 5", "rejected");
    w.Accept(5);
    if (!w.Check(3)) return test_helper("check 3", "rejected");
    w.Accept(3);
    if (!w.Check(4)) return test_helper("check 4", "rejected");
    w.Accept(4);

    bool replay_rejected = !w.Check(3);
    return test_helper("1", std::to_string(replay_rejected));
}

// Counter that has fallen behind the window is rejected
bool ReplayWindowTest_TooOld_Rejected() {
    ReplayWindow w;
    // Advance last_ to 3000 by accepting it
    w.Accept(3000);
    // counter 952: 952 + 2048 = 3000 <= 3000 → outside window → rejected
    return test_helper("1", std::to_string(!w.Check(952)));
}

// Large jump forward is accepted, old counters within new window still work
bool ReplayWindowTest_LargeJump_ThenOldInWindow() {
    ReplayWindow w;
    w.Accept(5);
    // Jump to 1000
    if (!w.Check(1000)) return test_helper("check 1000", "rejected");
    w.Accept(1000);
    // Counter 5 is now 995 steps behind — within the 2048 window, not yet seen via Accept(5)...
    // Wait, Accept(5) was called before the jump, so bitmap recorded it.
    // After jump to 1000: bitmap[1000 - 5] = bitmap[995] should be set (it was set before shift).
    // So counter 5 should be rejected.
    bool old_rejected = !w.Check(5);
    // Counter 999 (just below last_) is within window and unseen
    bool near_accepted = w.Check(999);
    return test_helper("1", std::to_string(old_rejected && near_accepted));
}

// Window boundary: last_ - 2047 is accepted (just inside); last_ - 2048 is rejected (just outside)
bool ReplayWindowTest_BoundaryEdge() {
    ReplayWindow w;
    w.Accept(3000);

    // last_ - 2047 = 953 → 953 + 2048 = 3001 > 3000 → inside window → accepted (if unseen)
    bool inside_accepted = w.Check(953);
    // last_ - 2048 = 952 → 952 + 2048 = 3000 <= 3000 → outside window → rejected
    bool outside_rejected = !w.Check(952);

    return test_helper("1", std::to_string(inside_accepted && outside_rejected));
}

// Counter exactly equal to last_ is rejected after Accept
bool ReplayWindowTest_ExactLastCounter_RejectedAfterAccept() {
    ReplayWindow w;
    w.Accept(50);
    // bitmap_[0] was set for counter 50
    return test_helper("1", std::to_string(!w.Check(50)));
}

// Multiple jumps: window shifts correctly across non-contiguous accepts
bool ReplayWindowTest_MultipleJumps_Consistent() {
    ReplayWindow w;
    w.Accept(100);
    w.Accept(200);
    w.Accept(300);

    // 100 is 200 steps behind last_ (300) — within window, should be rejected (seen)
    bool c100_rejected = !w.Check(100);
    // 200 also within window, rejected
    bool c200_rejected = !w.Check(200);
    // 301 is new
    bool c301_accepted = w.Check(301);
    // 50 is 250 steps behind — within window, unseen → accepted
    bool c50_accepted = w.Check(50);

    return test_helper("1", std::to_string(c100_rejected && c200_rejected &&
                                           c301_accepted && c50_accepted));
}

#endif // _PQVPN_TESTS_REPLAY_WINDOW_TESTS_HPP_
