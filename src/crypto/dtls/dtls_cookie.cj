package jinguissl_core.crypto.dtls

import std.collection.ArrayList
import jinguissl_core.crypto.digest.{hmac, HashAlgorithm}
import jinguissl_core.crypto.error.{CryptoException, CryptoErrorCode}
import jinguissl_core.crypto.utils.csprngBytes

// ============================================================================
// DTLS Cookie Secret Rotation And Binding 
// ============================================================================
//
// RFC 6347 §4.2.1 requires the DTLS cookie to be:
//   - derived from a private, unpredictable, cryptographically random secret
//     (NOT the public server random)
//   - bound to canonical client IP, port, DTLS version, and relevant
//     ClientHello material (cipher suites, extensions, random)
//   - expiry-bounded so a captured cookie cannot be replayed indefinitely
//   - rotatable with a previous-key overlap window so rotation does not
//     break in-flight handshakes
//
// Cookie wire format (self-contained, no external state lookup on verify):
//   [1 byte secretId][8 bytes timestampMs (BE)][32 bytes HMAC-SHA256]
//
// The secretId selects which secret to use (0 = current, 1 = previous
// during overlap). The timestamp is the cookie's issuance time; the
// verifier rejects cookies older than `ttlMs`. The HMAC is computed over
// `secretId || timestamp || clientIp || clientPort || version ||
// clientRandom || cipherSuites || srtpProfiles` using the selected secret.
//
// The manager holds at most two secrets: `_current` and `_previous`.
// `rotate()` promotes current to previous and generates a fresh current.
// The previous secret remains usable for `rotationOverlapMs` after
// rotation; after that, cookies bearing secretId=1 are rejected.
// ============================================================================

/// Cookie secret: a 32-byte CSPRNG-generated key plus its creation time.
public class DtlsCookieSecret {
    public let secret: Array<Byte>
    public let createdAtMs: Int64

    public init(secret: Array<Byte>, createdAtMs: Int64) {
        this.secret = secret
        this.createdAtMs = createdAtMs
    }
}

/// Default cookie secret size (256 bits).
public let DTLS_COOKIE_SECRET_LEN: Int64 = 32
/// Default cookie time-to-live (5 minutes). RFC 6347 §4.2.1 does not
/// mandate a specific value; 5 minutes is a conservative default that
/// bounds replay while tolerating handshake retransmit latency.
public let DTLS_COOKIE_DEFAULT_TTL_MS: Int64 = 300_000
/// Default rotation overlap window (2 minutes). During this window after
/// a rotation, cookies bearing the previous secretId are still accepted.
public let DTLS_COOKIE_DEFAULT_ROTATION_OVERLAP_MS: Int64 = 120_000

/// Cookie manager: holds the current and previous secrets, generates
/// bound cookies, and verifies them with expiry + rotation enforcement.
public class DtlsCookieManager {
    var _current: DtlsCookieSecret
    var _previous: ?DtlsCookieSecret
    let _ttlMs: Int64
    let _rotationOverlapMs: Int64
    private var previousValidFrom: Int64 = 0

    /// Construct a fresh manager with a CSPRNG-generated current secret.
    /// `ttlMs` bounds cookie lifetime; `rotationOverlapMs` bounds how
    /// long the previous secret remains valid after `rotate()`.
    public init(secretSize: Int64, ttlMs: Int64, rotationOverlapMs: Int64) {
        if (secretSize < 16) {
            throw CryptoException(CryptoErrorCode.InvalidArgument,
                "DTLS cookie secret size must be >= 16 bytes, got " + secretSize.toString())
        }
        if (ttlMs <= 0) {
            throw CryptoException(CryptoErrorCode.InvalidArgument,
                "DTLS cookie ttlMs must be positive, got " + ttlMs.toString())
        }
        if (rotationOverlapMs < 0) {
            throw CryptoException(CryptoErrorCode.InvalidArgument,
                "DTLS cookie rotationOverlapMs must be >= 0, got " + rotationOverlapMs.toString())
        }
        this._current = DtlsCookieSecret(csprngBytes(secretSize), 0)
        this._previous = None
        this._ttlMs = ttlMs
        this._rotationOverlapMs = rotationOverlapMs
    }

    /// The current secret's creation time (for test inspection).
    public prop currentCreatedAtMs: Int64 {
        get() { _current.createdAtMs }
    }

    /// True iff a previous secret is currently retained.
    public prop hasPrevious: Bool {
        get() {
            match (_previous) {
                case Some(_) => true
                case None => false
            }
        }
    }

    /// Build the HMAC input buffer for a cookie. The input is:
    ///   secretId (1) || timestamp (8 BE) || clientIp || clientPort (2 BE)
    ///   || version (2 BE) || clientRandom || cipherSuites || srtpProfiles
    private func buildHmacInput(secretId: UInt8, timestampMs: Int64,
        clientIp: Array<Byte>, clientPort: UInt16, version: UInt16,
        clientRandom: Array<Byte>, cipherSuites: Array<UInt16>,
        srtpProfiles: Array<UInt16>): Array<Byte> {
        let buf = ArrayList<Byte>()
        buf.add(secretId)
        // timestampMs as 8-byte big-endian
        buf.add(UInt8(UInt64(timestampMs) >> UInt64(56) & UInt64(0xFF)))
        buf.add(UInt8(UInt64(timestampMs) >> UInt64(48) & UInt64(0xFF)))
        buf.add(UInt8(UInt64(timestampMs) >> UInt64(40) & UInt64(0xFF)))
        buf.add(UInt8(UInt64(timestampMs) >> UInt64(32) & UInt64(0xFF)))
        buf.add(UInt8(UInt64(timestampMs) >> UInt64(24) & UInt64(0xFF)))
        buf.add(UInt8(UInt64(timestampMs) >> UInt64(16) & UInt64(0xFF)))
        buf.add(UInt8(UInt64(timestampMs) >> UInt64(8) & UInt64(0xFF)))
        buf.add(UInt8(UInt64(timestampMs) & UInt64(0xFF)))
        // client IP (canonical, caller-supplied)
        for (b in clientIp) { buf.add(b) }
        // client port (2 BE)
        buf.add(UInt8((clientPort >> 8) & UInt16(0xFF)))
        buf.add(UInt8(clientPort & UInt16(0xFF)))
        // DTLS version (2 BE)
        buf.add(UInt8((version >> 8) & UInt16(0xFF)))
        buf.add(UInt8(version & UInt16(0xFF)))
        // client random
        for (b in clientRandom) { buf.add(b) }
        // cipher suites (each 2 BE)
        for (cs in cipherSuites) {
            buf.add(UInt8((cs >> 8) & UInt16(0xFF)))
            buf.add(UInt8(cs & UInt16(0xFF)))
        }
        // srtp profiles (each 2 BE)
        for (p in srtpProfiles) {
            buf.add(UInt8((p >> 8) & UInt16(0xFF)))
            buf.add(UInt8(p & UInt16(0xFF)))
        }
        buf.toArray()
    }

    /// Generate a cookie bound to the supplied client identity and
    /// ClientHello material. `nowMs` is the caller-supplied current
    /// time in milliseconds (injecting time externally makes the
    /// manager deterministic under test).
    public func generateCookie(clientIp: Array<Byte>, clientPort: UInt16,
        version: UInt16, clientRandom: Array<Byte>,
        cipherSuites: Array<UInt16>, srtpProfiles: Array<UInt16>,
        nowMs: Int64): Array<Byte> {
        let secretId = UInt8(0)  // current secret
        let input = buildHmacInput(secretId, nowMs, clientIp, clientPort,
            version, clientRandom, cipherSuites, srtpProfiles)
        let mac = hmac(HashAlgorithm.SHA256, _current.secret, input)
        // Cookie = secretId (1) || timestamp (8 BE) || HMAC (32)
        let out = Array<Byte>(1 + 8 + mac.size, repeat: 0)
        out[0] = secretId
        out[1] = UInt8(UInt64(nowMs) >> UInt64(56) & UInt64(0xFF))
        out[2] = UInt8(UInt64(nowMs) >> UInt64(48) & UInt64(0xFF))
        out[3] = UInt8(UInt64(nowMs) >> UInt64(40) & UInt64(0xFF))
        out[4] = UInt8(UInt64(nowMs) >> UInt64(32) & UInt64(0xFF))
        out[5] = UInt8(UInt64(nowMs) >> UInt64(24) & UInt64(0xFF))
        out[6] = UInt8(UInt64(nowMs) >> UInt64(16) & UInt64(0xFF))
        out[7] = UInt8(UInt64(nowMs) >> UInt64(8) & UInt64(0xFF))
        out[8] = UInt8(UInt64(nowMs) & UInt64(0xFF))
        for (i in 0..mac.size) {
            out[9 + i] = mac[i]
        }
        out
    }

    /// Constant-time-ish byte comparison (early-exit on length mismatch,
    /// but full-scan on equal length to avoid timing leakage of the
    /// first differing byte position).
    private func constantTimeEquals(a: Array<Byte>, b: Array<Byte>): Bool {
        if (a.size != b.size) {
            return false
        }
        var diff = UInt8(0)
        for (i in 0..a.size) {
            diff = diff | (a[i] ^ b[i])
        }
        diff == UInt8(0)
    }

    /// Verify a cookie against the current (and previous during overlap)
    /// secret. Returns true iff the cookie is well-formed, not expired,
    /// and the HMAC matches. Returns false on any mismatch (no throw —
    /// the caller is expected to treat a false return as "send
    /// HelloVerifyRequest with a fresh cookie").
    ///
    /// secretId=0 cookies are tried against the current secret first;
    /// if that fails and a previous secret exists within its overlap
    /// window, the previous secret is also tried. This allows cookies
    /// issued just before a `rotate()` to remain valid for the overlap
    /// window without the client re-fetching a fresh cookie.
    public func verifyCookie(cookie: Array<Byte>, clientIp: Array<Byte>,
        clientPort: UInt16, version: UInt16, clientRandom: Array<Byte>,
        cipherSuites: Array<UInt16>, srtpProfiles: Array<UInt16>,
        nowMs: Int64): Bool {
        // Cookie = secretId (1) || timestamp (8 BE) || HMAC (32)
        if (cookie.size != 1 + 8 + 32) {
            return false
        }
        let secretId = cookie[0]
        let timestampMs = Int64((UInt64(cookie[1]) << UInt64(56)) |
                                (UInt64(cookie[2]) << UInt64(48)) |
                                (UInt64(cookie[3]) << UInt64(40)) |
                                (UInt64(cookie[4]) << UInt64(32)) |
                                (UInt64(cookie[5]) << UInt64(24)) |
                                (UInt64(cookie[6]) << UInt64(16)) |
                                (UInt64(cookie[7]) << UInt64(8)) |
                                 UInt64(cookie[8]))

        // Expiry check: reject cookies older than ttlMs.
        if (nowMs - timestampMs > _ttlMs) {
            return false
        }
        // Defensive: reject cookies with a future timestamp beyond ttlMs
        // (clock-skew tolerance). A small future skew is allowed; a large
        // one is treated as forgery.
        if (timestampMs - nowMs > _ttlMs) {
            return false
        }

        let actualMac = Array<Byte>(32, repeat: 0)
        for (i in 0..32) {
            actualMac[i] = cookie[9 + i]
        }

        if (secretId == UInt8(0)) {
            // Try the current secret first.
            let input = buildHmacInput(secretId, timestampMs, clientIp, clientPort,
                version, clientRandom, cipherSuites, srtpProfiles)
            let macCurrent = hmac(HashAlgorithm.SHA256, _current.secret, input)
            if (constantTimeEquals(macCurrent, actualMac)) {
                return true
            }
            // Fallback: cookies issued under the previous current secret
            // (before the most recent rotate) still carry secretId=0.
            // Accept them while the previous secret is within its overlap
            // window so rotation does not break in-flight handshakes.
            match (_previous) {
                case Some(prev) =>
                    if (nowMs >= previousValidFrom && nowMs - previousValidFrom <= _rotationOverlapMs) {
                        let macPrev = hmac(HashAlgorithm.SHA256, prev.secret, input)
                        return constantTimeEquals(macPrev, actualMac)
                    }
                case None =>
                    ()  // No previous secret to fall back to.
            }
            return false
        } else if (secretId == UInt8(1)) {
            // Explicit previous-secret cookie. Only valid within overlap.
            match (_previous) {
                case Some(prev) =>
                    if (nowMs < previousValidFrom || nowMs - previousValidFrom > _rotationOverlapMs) {
                        return false
                    }
                    let input = buildHmacInput(secretId, timestampMs, clientIp, clientPort,
                        version, clientRandom, cipherSuites, srtpProfiles)
                    let macPrev = hmac(HashAlgorithm.SHA256, prev.secret, input)
                    return constantTimeEquals(macPrev, actualMac)
                case None =>
                    return false
            }
        } else {
            return false
        }
    }

    /// Rotate to a fresh current secret. The previous current becomes
    /// the previous (retained for `rotationOverlapMs`). `nowMs` is the
    /// caller-supplied current time.
    public func rotate(nowMs: Int64): Unit {
        if (nowMs < _current.createdAtMs) {
            throw CryptoException(CryptoErrorCode.InvalidArgument, "cookie rotation clock moved backwards")
        }
        retirePrevious()
        previousValidFrom = nowMs
        _previous = _current
        _current = DtlsCookieSecret(csprngBytes(DTLS_COOKIE_SECRET_LEN), nowMs)
    }

    /// Drop the previous secret explicitly (e.g. after the overlap
    /// window has expired). After this call, cookies bearing
    /// secretId=1 are rejected.
    public func retirePrevious(): Unit {
        match (_previous) {
            case Some(previous) => for (i in 0..previous.secret.size) { previous.secret[i] = 0 }
            case None => ()
        }
        _previous = None
    }
}
