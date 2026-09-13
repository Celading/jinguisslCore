package jinguissl_core.crypto.dtls

import std.collection.HashSet
import jinguissl_core.crypto.error.{CryptoException, CryptoErrorCode}

// ============================================================================
// DTLS Per-Epoch Receive Anti-Replay Window 
// ============================================================================
//
// RFC 6347 §3.3 / §4.1 require each DTLS epoch to enforce a receive
// anti-replay window. The receiver tracks the highest sequence number
// seen so far (`leftEdge`/`rightEdge`) and a bit window of recently
// accepted seqs. A record is accepted iff:
//   - its seq is within the window (rightEdge - windowSize + 1 .. rightEdge)
//     and has not been seen before; OR
//   - its seq is above the window (advance the window forward).
//
// Records below the window are stale (rejected as potential replays).
// Records already seen within the window are duplicates (rejected).
//
// Per RFC 6347 §4.1 the 64-bit sequence number is composed of
// (epoch (16 bits) || seq (48 bits)). The replay check is per-epoch;
// each new epoch starts a fresh window.
// ============================================================================

/// Default anti-replay window size per RFC 6347 §3.3 recommendation.
public let DTLS_DEFAULT_REPLAY_WINDOW_SIZE: Int64 = 64

/// Per-epoch receive anti-replay window.
///
/// Tracks the highest sequence number seen (`rightEdge`) and a HashSet
/// of all seqs currently inside the window. A seq is accepted iff:
///   - it is greater than `rightEdge` (advance the window forward), OR
///   - it is within `[rightEdge - windowSize + 1, rightEdge]` and not
///     already in the window.
///
/// A seq below the window (stale) or already in the window (duplicate)
/// is rejected with `CryptoException(InvalidArgument)`.
public class DtlsReplayWindow {
    public let epoch: UInt16
    public let windowSize: Int64
    public var rightEdge: UInt48
    let _seen: HashSet<UInt64>

    /// Initialize a fresh window for a new epoch. The window starts
    /// "empty" with rightEdge = 0 and no seqs accepted yet. The first
    /// seq received (any value >= 1, or 0) will be accepted and become
    /// the new rightEdge.
    public init(epoch: UInt16, windowSize: Int64)    {
        if (windowSize <= 0) {
            throw CryptoException(CryptoErrorCode.InvalidArgument,
                "DTLS replay window size must be positive, got " + windowSize.toString())
        }
        this.epoch = epoch
        this.windowSize = windowSize
        this.rightEdge = UInt48(UInt64(0))
        this._seen = HashSet<UInt64>()
    }

    /// Returns true iff `seq` has been recorded as seen in this window.
    public func contains(seq: UInt48): Bool {
        _seen.contains(seq.toUInt64())
    }

    /// Returns true iff this is the first record in the window (no seq
    /// has been accepted yet).
    public func isEmpty(): Bool {
        _seen.size == 0
    }

    /// Validate `seq` against the anti-replay window and, if valid,
    /// record it as seen. Throws CryptoException(InvalidArgument) on
    /// stale (below window) or duplicate (already seen) seqs.
    public func checkAndRecord(seq: UInt48): Unit {
        let seq64 = seq.toUInt64()
        if (isEmpty()) {
            rightEdge = seq
            _seen.add(seq64)
            return
        }

        if (seq > rightEdge) {
            rightEdge = seq
            let leftEdge = computeLeftEdge()
            let leftEdge64 = leftEdge.toUInt64()
            let snapshot = Array<UInt64>(_seen.size, repeat: UInt64(0))
            var idx = 0
            for (s in _seen) {
                snapshot[idx] = s
                idx += 1
            }
            for (s in snapshot) {
                if (s < leftEdge64) {
                    _seen.remove(s)
                }
            }
            _seen.add(seq64)
            return
        }

        let leftEdge = computeLeftEdge()
        if (seq < leftEdge) {
            throw CryptoException(CryptoErrorCode.InvalidArgument,
                "DTLS replay window: stale seq " + seq.toString() +
                " below window [" + leftEdge.toString() + ", " +
                rightEdge.toString() + "] for epoch " + epoch.toString())
        }

        if (_seen.contains(seq64)) {
            throw CryptoException(CryptoErrorCode.InvalidArgument,
                "DTLS replay window: duplicate seq " + seq.toString() +
                " for epoch " + epoch.toString())
        }

        _seen.add(seq64)
    }

    /// Compute the current left edge (lowest seq still in the window).
    /// May underflow to 0 if rightEdge < windowSize.
    func computeLeftEdge(): UInt48 {
        let right = rightEdge.toUInt64()
        if (right < UInt64(windowSize)) {
            return UInt48(UInt64(0))
        }
        UInt48(right - UInt64(windowSize) + UInt64(1))
    }

    /// Number of seqs currently recorded as seen in the window.
    public func seenCount(): Int64 {
        _seen.size
    }

    /// Reset the window to its initial state (used on epoch transition
    /// or session reset).
    public func reset(): Unit {
        rightEdge = UInt48(UInt64(0))
        _seen.clear()
    }
}

/// Per-session multi-epoch replay window manager. Tracks one
/// `DtlsReplayWindow` per active epoch. Old epochs are retired when
/// a new epoch becomes current.
public class DtlsReplayWindowManager {
    var _current: DtlsReplayWindow
    var _previous: ?DtlsReplayWindow = None

    public init(initialEpoch: UInt16, windowSize: Int64) {
        _current = DtlsReplayWindow(initialEpoch, windowSize)
    }

    /// The current-epoch replay window.
    public prop current: DtlsReplayWindow {
        get() { _current }
    }

    /// The previous-epoch replay window, if any (None before the first
    /// epoch transition).
    public prop previous: ?DtlsReplayWindow {
        get() { _previous }
    }

    /// Validate and record a received seq in the current epoch's window.
    public func checkAndRecord(epoch: UInt16, seq: UInt48): Unit {
        if (epoch != _current.epoch) {
            throw CryptoException(CryptoErrorCode.InvalidArgument,
                "DTLS replay: epoch mismatch, expected " + _current.epoch.toString() +
                " got " + epoch.toString())
        }
        _current.checkAndRecord(seq)
    }

    /// Transition to a new epoch. The current window becomes the
    /// previous window, and a fresh window is created for the new
    /// epoch. The previous window remains queryable for a bounded
    /// time so late records in the old epoch can still be validated
    /// by the caller (the caller is responsible for routing the
    /// record to the correct epoch's window).
    public func transitionTo(newEpoch: UInt16, windowSize: Int64): Unit {
        if (newEpoch <= _current.epoch) {
            throw CryptoException(CryptoErrorCode.InvalidArgument,
                "DTLS replay: new epoch must be greater than current, got " +
                newEpoch.toString() + " <= " + _current.epoch.toString())
        }
        _previous = _current
        _current = DtlsReplayWindow(newEpoch, windowSize)
    }

    /// Validate and record a received seq in the previous epoch's
    /// window. Used for late records that arrive in the old epoch
    /// after the transition. Throws if there is no previous window
    /// or the supplied epoch does not match the previous window.
    public func checkAndRecordPrevious(epoch: UInt16, seq: UInt48): Unit {
        match (_previous) {
            case Some(w) =>
                if (w.epoch != epoch) {
                    throw CryptoException(CryptoErrorCode.InvalidArgument,
                        "DTLS replay: previous epoch mismatch, expected " +
                        w.epoch.toString() + " got " + epoch.toString())
                }
                w.checkAndRecord(seq)
            case None =>
                throw CryptoException(CryptoErrorCode.InvalidArgument,
                    "DTLS replay: no previous epoch window to check")
        }
    }

    /// Retire the previous epoch window. Called by the caller after
    /// the bounded overlap window has expired.
    public func retirePrevious(): Unit {
        _previous = None
    }
}
