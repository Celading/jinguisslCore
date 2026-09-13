package jinguissl_core.dtls_tests

import std.unittest.*
import std.unittest.testmacro.*
import jinguissl_core.crypto.dtls.*
import jinguissl_core.crypto.error.CryptoException

// ============================================================================
// Per-Epoch Receive Anti-Replay Window — regression tests
// ============================================================================

private func mkSeq(v: UInt64): UInt48 {
    UInt48(v)
}

@Test
public class DtlsReplayWindowBasicTestSuite {

    @TestCase
    public func testEmptyWindow_AcceptsAnySeq(): Unit {
        let w = DtlsReplayWindow(UInt16(0), 4)
        @Assert(w.isEmpty(), true)
        w.checkAndRecord(mkSeq(42))
        @Assert(w.isEmpty(), false)
        @Assert(w.rightEdge, mkSeq(42))
        @Assert(w.seenCount(), 1)
    }

    @TestCase
    public func testRejectsInvalidWindowSize(): Unit {
        var threw = false
        try {
            _ = DtlsReplayWindow(UInt16(0), 0)
        } catch (e: CryptoException) {
            threw = true
        }
        @Assert(threw, true)

        var threw2 = false
        try {
            _ = DtlsReplayWindow(UInt16(0), -1)
        } catch (e: CryptoException) {
            threw2 = true
        }
        @Assert(threw2, true)
    }

    // Acceptance: detect and reject duplicates deterministically.
    @TestCase
    public func testDuplicate_Rejected(): Unit {
        let w = DtlsReplayWindow(UInt16(0), 8)
        w.checkAndRecord(mkSeq(1))
        w.checkAndRecord(mkSeq(2))
        w.checkAndRecord(mkSeq(3))

        var threw = false
        try {
            w.checkAndRecord(mkSeq(2))
        } catch (e: CryptoException) {
            threw = true
        }
        @Assert(threw, true)
        @Assert(w.seenCount(), 3)
    }

    // Acceptance: detect and reject stale seqs (below window).
    @TestCase
    public func testStale_Rejected(): Unit {
        let w = DtlsReplayWindow(UInt16(0), 4)
        // Push rightEdge forward to 10.
        w.checkAndRecord(mkSeq(10))
        // Window is now [10-4+1=7 .. 10]. Seq 6 is stale.
        var threw = false
        try {
            w.checkAndRecord(mkSeq(6))
        } catch (e: CryptoException) {
            threw = true
        }
        @Assert(threw, true)
    }

    // Acceptance: handle future seqs (above window).
    @TestCase
    public func testFuture_AcceptedAndAdvancesWindow(): Unit {
        let w = DtlsReplayWindow(UInt16(0), 4)
        w.checkAndRecord(mkSeq(1))
        w.checkAndRecord(mkSeq(2))
        // Future seq advances the window.
        w.checkAndRecord(mkSeq(100))
        @Assert(w.rightEdge, mkSeq(100))
        // Old seqs below the new window are now stale.
        var threw = false
        try {
            w.checkAndRecord(mkSeq(2))
        } catch (e: CryptoException) {
            threw = true
        }
        @Assert(threw, true)
    }

    // Acceptance: handle reordered records within the window.
    @TestCase
    public func testReordered_WithinWindow_Accepted(): Unit {
        let w = DtlsReplayWindow(UInt16(0), 8)
        w.checkAndRecord(mkSeq(1))
        w.checkAndRecord(mkSeq(2))
        w.checkAndRecord(mkSeq(3))
        // Reordered: receive 5 before 4.
        w.checkAndRecord(mkSeq(5))
        @Assert(w.rightEdge, mkSeq(5))
        // 4 is still within the window and not seen — accept.
        w.checkAndRecord(mkSeq(4))
        @Assert(w.seenCount(), 5)
    }

    // Acceptance: wrap-boundary handling. Seq near UInt48 max.
    @TestCase
    public func testWrapBoundary_NearMax(): Unit {
        let w = DtlsReplayWindow(UInt16(0), 4)
        let nearMax = UInt64(0xFFFFFFFFFFFF)  // 48-bit max
        w.checkAndRecord(mkSeq(nearMax))
        @Assert(w.rightEdge, mkSeq(nearMax))
        // A seq just below nearMax should still be in the window.
        w.checkAndRecord(mkSeq(nearMax - 1))
        @Assert(w.seenCount(), 2)
    }
}

@Test
public class DtlsReplayWindowManagerTestSuite {

    // Acceptance: epoch-transition — new epoch starts a fresh window.
    @TestCase
    public func testEpochTransition_FreshWindow(): Unit {
        let mgr = DtlsReplayWindowManager(UInt16(0), 8)
        mgr.checkAndRecord(UInt16(0), mkSeq(1))
        mgr.checkAndRecord(UInt16(0), mkSeq(2))
        @Assert(mgr.current.seenCount(), 2)
        @Assert(mgr.current.epoch, UInt16(0))

        mgr.transitionTo(UInt16(1), 8)
        @Assert(mgr.current.epoch, UInt16(1))
        @Assert(mgr.current.isEmpty(), true)
        match (mgr.previous) {
            case Some(w) => @Assert(w.epoch, UInt16(0))
            case None => @Assert(false, true)
        }
    }

    // Acceptance: epoch-transition — old epoch windows are retired cleanly.
    @TestCase
    public func testEpochTransition_OldEpochRetired(): Unit {
        let mgr = DtlsReplayWindowManager(UInt16(0), 8)
        mgr.checkAndRecord(UInt16(0), mkSeq(1))
        mgr.transitionTo(UInt16(1), 8)
        mgr.retirePrevious()
        match (mgr.previous) {
            case Some(_) => @Assert(false, true)
            case None => ()
        }
    }

    // Acceptance: late records in the previous epoch can still be checked.
    @TestCase
    public func testLateRecordInPreviousEpoch_Accepted(): Unit {
        let mgr = DtlsReplayWindowManager(UInt16(0), 8)
        mgr.checkAndRecord(UInt16(0), mkSeq(1))
        mgr.checkAndRecord(UInt16(0), mkSeq(2))
        mgr.transitionTo(UInt16(1), 8)
        // A late record arrives in epoch 0.
        mgr.checkAndRecordPrevious(UInt16(0), mkSeq(3))
        match (mgr.previous) {
            case Some(w) => @Assert(w.seenCount(), 3)
            case None => @Assert(false, true)
        }
    }

    // Epoch mismatch in current window is rejected.
    @TestCase
    public func testEpochMismatchCurrent_Rejected(): Unit {
        let mgr = DtlsReplayWindowManager(UInt16(0), 8)
        var threw = false
        try {
            mgr.checkAndRecord(UInt16(1), mkSeq(1))
        } catch (e: CryptoException) {
            threw = true
        }
        @Assert(threw, true)
    }

    // Backward epoch transition is rejected.
    @TestCase
    public func testBackwardEpochTransition_Rejected(): Unit {
        let mgr = DtlsReplayWindowManager(UInt16(5), 8)
        var threw = false
        try {
            mgr.transitionTo(UInt16(3), 8)
        } catch (e: CryptoException) {
            threw = true
        }
        @Assert(threw, true)
    }

    // checkAndRecordPrevious with no previous window is rejected.
    @TestCase
    public func testCheckPrevious_NoPrevious_Rejected(): Unit {
        let mgr = DtlsReplayWindowManager(UInt16(0), 8)
        var threw = false
        try {
            mgr.checkAndRecordPrevious(UInt16(0), mkSeq(1))
        } catch (e: CryptoException) {
            threw = true
        }
        @Assert(threw, true)
    }

    // Stored counters are enforced — a duplicate after window advance
    // is still rejected (not just tracked passively).
    @TestCase
    public func testStoredCountersAreEnforced(): Unit {
        let w = DtlsReplayWindow(UInt16(0), 4)
        w.checkAndRecord(mkSeq(1))
        w.checkAndRecord(mkSeq(2))
        w.checkAndRecord(mkSeq(3))
        w.checkAndRecord(mkSeq(4))
        // Window is full. Advance.
        w.checkAndRecord(mkSeq(10))
        // 4 is now below the window [7..10] — rejected.
        var threw = false
        try {
            w.checkAndRecord(mkSeq(4))
        } catch (e: CryptoException) {
            threw = true
        }
        @Assert(threw, true)
    }

    // Reset clears the window.
    @TestCase
    public func testReset_ClearsWindow(): Unit {
        let w = DtlsReplayWindow(UInt16(0), 8)
        w.checkAndRecord(mkSeq(1))
        w.checkAndRecord(mkSeq(2))
        @Assert(w.isEmpty(), false)
        w.reset()
        @Assert(w.isEmpty(), true)
        @Assert(w.rightEdge, mkSeq(0))
    }
}
