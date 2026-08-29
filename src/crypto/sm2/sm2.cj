package jinguissl_core.crypto.sm2

import jinguissl_core.crypto.bignum.BigNum
import jinguissl_core.crypto.ecc.{sm2p256v1GeneratorMul, sm2p256v1PointOnCurve, sm2p256v1ScalarMul}
import jinguissl_core.crypto.error.{CryptoException, CryptoErrorCode}
import jinguissl_core.crypto.sm3.{Sm3Context, sm3, sm3Kdf}
import jinguissl_core.crypto.utils.{constantTimeEquals, randomSeed}

private let SM2_P = BigNum.fromHex("FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFF")
private let SM2_A = BigNum.fromHex("FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFC")
private let SM2_B = BigNum.fromHex("28E9FA9E9D9F5E344D5A9E4BCF6509A7F39789F515AB8F92DDBCBD414D940E93")
private let SM2_GX = BigNum.fromHex("32C4AE2C1F1981195F9904466A39C9948FE30BBFF2660BE1715A4589334C74C7")
private let SM2_GY = BigNum.fromHex("BC3736A2F4F6779C59BDCEE36B692153D0A9877CC62A474002DF32E52139F0A0")
private let SM2_N = BigNum.fromHex("FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFF7203DF6B21C6052B53BBF40939D54123")
private let SM2_FIELD_SIZE: Int64 = 32
private let SM2_UNCOMPRESSED_SIZE: Int64 = 65

/** Validated sm2p256v1 public key. */
public class Sm2PublicKey {
    public let x: BigNum
    public let y: BigNum

    public init(x: BigNum, y: BigNum) {
        if (!sm2p256v1PointOnCurve(x, y)) {
            throw CryptoException(InvalidArgument, "SM2 public key is not on sm2p256v1")
        }
        this.x = x
        this.y = y
    }
}

/** Validated sm2p256v1 private scalar. */
public class Sm2PrivateKey {
    public let scalar: BigNum

    public init(scalar: BigNum) {
        if (!scalarInRange(scalar)) {
            throw CryptoException(InvalidArgument, "SM2 private scalar must be in [1, n-1]")
        }
        this.scalar = scalar
    }
}

/** Result of one SM2 identity-bound key-exchange side. */
public class Sm2KeyExchangeResult {
    public let key: Array<Byte>
    public let sendConfirmation: Array<Byte>
    public let expectedPeerConfirmation: Array<Byte>

    public init(
        key: Array<Byte>,
        sendConfirmation: Array<Byte>,
        expectedPeerConfirmation: Array<Byte>
    ) {
        this.key = key
        this.sendConfirmation = sendConfirmation
        this.expectedPeerConfirmation = expectedPeerConfirmation
    }
}

/** Generate an SM2 private key from the runtime CSPRNG. */
public func sm2GeneratePrivateKey(): Sm2PrivateKey {
    Sm2PrivateKey(randomScalar())
}

/** Derive the public key corresponding to an SM2 private key. */
public func sm2PublicKey(privateKey: Sm2PrivateKey): Sm2PublicKey {
    let (x, y, infinity) = sm2p256v1GeneratorMul(privateKey.scalar)
    if (infinity) {
        throw CryptoException(InternalError, "SM2 public key derivation reached infinity")
    }
    Sm2PublicKey(x, y)
}

/** Encode an SM2 public key as an uncompressed SEC1 point. */
public func sm2PublicKeyToUncompressed(publicKey: Sm2PublicKey): Array<Byte> {
    let output = Array<Byte>(SM2_UNCOMPRESSED_SIZE, repeat: UInt8(0))
    output[0] = UInt8(0x04)
    copyInto(publicKey.x.toBytesBE(paddedLen: SM2_FIELD_SIZE), output, 1)
    copyInto(publicKey.y.toBytesBE(paddedLen: SM2_FIELD_SIZE), output, 33)
    output
}

/** Decode and validate an uncompressed SEC1 SM2 public point. */
public func sm2PublicKeyFromUncompressed(encoded: Array<Byte>): Sm2PublicKey {
    if (encoded.size != SM2_UNCOMPRESSED_SIZE || encoded[0] != UInt8(0x04)) {
        throw CryptoException(ParseError, "SM2 public key must be a 65-byte uncompressed point")
    }
    Sm2PublicKey(
        BigNum.fromBytesBE(encoded[1..33]),
        BigNum.fromBytesBE(encoded[33..65])
    )
}

/** Compute the SM2 user-binding digest ZA. */
public func sm2ComputeZa(identity: Array<Byte>, publicKey: Sm2PublicKey): Array<Byte> {
    if (identity.size > 8191) {
        throw CryptoException(InvalidArgument, "SM2 identity exceeds the 16-bit bit-length field")
    }
    let identityBits = UInt16(identity.size * 8)
    let context = Sm3Context()
    context.update([UInt8(identityBits >> 8), UInt8(identityBits & UInt16(0xFF))])
    context.update(identity)
    context.update(SM2_A.toBytesBE(paddedLen: SM2_FIELD_SIZE))
    context.update(SM2_B.toBytesBE(paddedLen: SM2_FIELD_SIZE))
    context.update(SM2_GX.toBytesBE(paddedLen: SM2_FIELD_SIZE))
    context.update(SM2_GY.toBytesBE(paddedLen: SM2_FIELD_SIZE))
    context.update(publicKey.x.toBytesBE(paddedLen: SM2_FIELD_SIZE))
    context.update(publicKey.y.toBytesBE(paddedLen: SM2_FIELD_SIZE))
    context.finish()
}

/** Sign a message with SM2 and an explicit signer identity. */
public func sm2Sign(
    privateKey: Sm2PrivateKey,
    identity: Array<Byte>,
    message: Array<Byte>
): (BigNum, BigNum) {
    if (privateKey.scalar.add(BigNum.one()).mod(SM2_N).isZero()) {
        throw CryptoException(InvalidArgument, "SM2 signing private scalar must be in [1, n-2]")
    }
    let publicKey = sm2PublicKey(privateKey)
    let e = sm2MessageScalar(identity, publicKey, message)
    var attempt: Int64 = 0
    while (attempt < 128) {
        let signature = sm2TrySignWithNonce(privateKey.scalar, e, randomScalar())
        if (signature.valid) {
            return (signature.r, signature.s)
        }
        attempt += 1
    }
    throw CryptoException(InternalError, "SM2 signing failed to generate a valid signature")
}

/** Verify an SM2 signature with an explicit signer identity. */
public func sm2Verify(
    publicKey: Sm2PublicKey,
    identity: Array<Byte>,
    message: Array<Byte>,
    r: BigNum,
    s: BigNum
): Bool {
    if (!scalarInRange(r) || !scalarInRange(s)) {
        return false
    }
    let t = r.add(s).mod(SM2_N)
    if (t.isZero()) {
        return false
    }
    let e = sm2MessageScalar(identity, publicKey, message)
    let first = generatorMul(s)
    let second = scalarMul(publicKey, t)
    let sum = pointAdd(first, second)
    if (sum.infinity) {
        return false
    }
    e.add(sum.x).mod(SM2_N).cmp(r) == 0
}

/**
 * Encrypt with SM2 and return the raw C1C3C2 encoding.
 *
 * C1 is an uncompressed 65-byte point and C3 is the 32-byte SM3 digest.
 */
public func sm2Encrypt(publicKey: Sm2PublicKey, plaintext: Array<Byte>): Array<Byte> {
    if (plaintext.size == 0) {
        throw CryptoException(InvalidArgument, "SM2 plaintext must not be empty")
    }
    var attempt: Int64 = 0
    while (attempt < 128) {
        let k = randomScalar()
        let c1 = generatorMul(k)
        let shared = scalarMul(publicKey, k)
        if (!c1.infinity && !shared.infinity) {
            let xy = pointCoordinates(shared)
            let mask = sm3Kdf(xy, plaintext.size)
            if (!allZero(mask)) {
                let c2 = xorBytes(plaintext, mask)
                let c3 = sm2CipherDigest(shared, plaintext)
                let output = Array<Byte>(SM2_UNCOMPRESSED_SIZE + 32 + plaintext.size, repeat: UInt8(0))
                output[0] = UInt8(0x04)
                copyInto(c1.x.toBytesBE(paddedLen: SM2_FIELD_SIZE), output, 1)
                copyInto(c1.y.toBytesBE(paddedLen: SM2_FIELD_SIZE), output, 33)
                copyInto(c3, output, SM2_UNCOMPRESSED_SIZE)
                copyInto(c2, output, SM2_UNCOMPRESSED_SIZE + 32)
                return output
            }
        }
        attempt += 1
    }
    throw CryptoException(InternalError, "SM2 encryption failed to derive a non-zero mask")
}

/** Decrypt a raw SM2 C1C3C2 ciphertext and verify C3 before returning plaintext. */
public func sm2Decrypt(privateKey: Sm2PrivateKey, ciphertext: Array<Byte>): Array<Byte> {
    if (ciphertext.size <= SM2_UNCOMPRESSED_SIZE + 32) {
        throw CryptoException(ParseError, "SM2 C1C3C2 ciphertext is too short")
    }
    let c1 = sm2PublicKeyFromUncompressed(ciphertext[..SM2_UNCOMPRESSED_SIZE])
    let c3 = ciphertext[SM2_UNCOMPRESSED_SIZE..SM2_UNCOMPRESSED_SIZE + 32]
    let c2 = ciphertext[SM2_UNCOMPRESSED_SIZE + 32..]
    let shared = scalarMul(c1, privateKey.scalar)
    if (shared.infinity) {
        throw CryptoException(ParseError, "SM2 ciphertext shared point is infinity")
    }
    let mask = sm3Kdf(pointCoordinates(shared), c2.size)
    if (allZero(mask)) {
        throw CryptoException(ParseError, "SM2 ciphertext derived an all-zero mask")
    }
    let plaintext = xorBytes(c2, mask)
    let expected = sm2CipherDigest(shared, plaintext)
    if (!constantTimeEquals(expected, c3)) {
        wipeBytes(plaintext)
        throw CryptoException(InvalidArgument, "SM2 ciphertext digest mismatch")
    }
    plaintext
}

/** Compute the raw 64-byte X||Y SM2 shared point. */
public func sm2SharedPoint(privateKey: Sm2PrivateKey, peerPublicKey: Sm2PublicKey): Array<Byte> {
    let shared = scalarMul(peerPublicKey, privateKey.scalar)
    if (shared.infinity) {
        throw CryptoException(InvalidArgument, "SM2 shared point is infinity")
    }
    pointCoordinates(shared)
}

/** Derive the 32-byte RFC 8998 curveSM2 ECDHE shared secret (the affine x-coordinate). */
public func sm2EcdhSharedSecret(privateKey: Sm2PrivateKey, peerPublicKey: Sm2PublicKey): Array<Byte> {
    let sharedPoint = sm2SharedPoint(privateKey, peerPublicKey)
    sharedPoint[..SM2_FIELD_SIZE]
}

/** Compare a received SM2 key-exchange confirmation without early byte exit. */
public func sm2VerifyConfirmation(expected: Array<Byte>, received: Array<Byte>): Bool {
    if (expected.size != 32 || received.size != 32) {
        return false
    }
    constantTimeEquals(expected, received)
}

/** Execute the initiator side of the identity-bound SM2 key exchange. */
public func sm2InitiatorKeyExchange(
    staticPrivateKey: Sm2PrivateKey,
    ephemeralPrivateKey: Sm2PrivateKey,
    peerStaticPublicKey: Sm2PublicKey,
    peerEphemeralPublicKey: Sm2PublicKey,
    selfIdentity: Array<Byte>,
    peerIdentity: Array<Byte>,
    keyLen: Int64
): Sm2KeyExchangeResult {
    let selfStaticPublic = sm2PublicKey(staticPrivateKey)
    let selfEphemeralPublic = sm2PublicKey(ephemeralPrivateKey)
    sm2KeyExchange(
        true,
        staticPrivateKey,
        ephemeralPrivateKey,
        selfStaticPublic,
        selfEphemeralPublic,
        peerStaticPublicKey,
        peerEphemeralPublicKey,
        selfIdentity,
        peerIdentity,
        keyLen
    )
}

/** Execute the responder side of the identity-bound SM2 key exchange. */
public func sm2ResponderKeyExchange(
    staticPrivateKey: Sm2PrivateKey,
    ephemeralPrivateKey: Sm2PrivateKey,
    peerStaticPublicKey: Sm2PublicKey,
    peerEphemeralPublicKey: Sm2PublicKey,
    selfIdentity: Array<Byte>,
    peerIdentity: Array<Byte>,
    keyLen: Int64
): Sm2KeyExchangeResult {
    let selfStaticPublic = sm2PublicKey(staticPrivateKey)
    let selfEphemeralPublic = sm2PublicKey(ephemeralPrivateKey)
    sm2KeyExchange(
        false,
        staticPrivateKey,
        ephemeralPrivateKey,
        selfStaticPublic,
        selfEphemeralPublic,
        peerStaticPublicKey,
        peerEphemeralPublicKey,
        selfIdentity,
        peerIdentity,
        keyLen
    )
}

private class Sm2Point {
    let x: BigNum
    let y: BigNum
    let infinity: Bool

    init(x: BigNum, y: BigNum) {
        this.x = x
        this.y = y
        this.infinity = false
    }

    init(infinity: Bool) {
        this.x = BigNum.zero()
        this.y = BigNum.zero()
        this.infinity = infinity
    }

    static func infinityPoint(): Sm2Point { Sm2Point(true) }
}

private class Sm2SignatureCandidate {
    let r: BigNum
    let s: BigNum
    let valid: Bool

    init(r: BigNum, s: BigNum, valid: Bool) {
        this.r = r
        this.s = s
        this.valid = valid
    }

    static func invalid(): Sm2SignatureCandidate {
        Sm2SignatureCandidate(BigNum.zero(), BigNum.zero(), false)
    }
}

private func sm2MessageScalar(
    identity: Array<Byte>, publicKey: Sm2PublicKey, message: Array<Byte>
): BigNum {
    let context = Sm3Context()
    context.update(sm2ComputeZa(identity, publicKey))
    context.update(message)
    BigNum.fromBytesBE(context.finish())
}

private func sm2TrySignWithNonce(
    privateScalar: BigNum, e: BigNum, nonce: BigNum
): Sm2SignatureCandidate {
    let point = generatorMul(nonce)
    if (point.infinity) {
        return Sm2SignatureCandidate.invalid()
    }
    let r = e.add(point.x).mod(SM2_N)
    if (r.isZero() || r.add(nonce).cmp(SM2_N) == 0) {
        return Sm2SignatureCandidate.invalid()
    }
    let inverse = BigNum.one().add(privateScalar).mod(SM2_N)
        .modInversePrimeFixedSchedule(SM2_N, 256)
    let s = inverse.mul(nonce.sub(r.mul(privateScalar))).mod(SM2_N)
    if (s.isZero()) {
        return Sm2SignatureCandidate.invalid()
    }
    Sm2SignatureCandidate(r, s, true)
}

private func sm2CipherDigest(shared: Sm2Point, plaintext: Array<Byte>): Array<Byte> {
    let context = Sm3Context()
    context.update(shared.x.toBytesBE(paddedLen: SM2_FIELD_SIZE))
    context.update(plaintext)
    context.update(shared.y.toBytesBE(paddedLen: SM2_FIELD_SIZE))
    context.finish()
}

private func sm2KeyExchange(
    initiator: Bool,
    staticPrivateKey: Sm2PrivateKey,
    ephemeralPrivateKey: Sm2PrivateKey,
    selfStaticPublic: Sm2PublicKey,
    selfEphemeralPublic: Sm2PublicKey,
    peerStaticPublic: Sm2PublicKey,
    peerEphemeralPublic: Sm2PublicKey,
    selfIdentity: Array<Byte>,
    peerIdentity: Array<Byte>,
    keyLen: Int64
): Sm2KeyExchangeResult {
    if (keyLen <= 0) {
        throw CryptoException(InvalidArgument, "SM2 key-exchange output length must be positive")
    }
    let twoPowW = BigNum.one().lshift(127)
    let selfReducedX = selfEphemeralPublic.x.mod(twoPowW).add(twoPowW)
    let peerReducedX = peerEphemeralPublic.x.mod(twoPowW).add(twoPowW)
    let t = staticPrivateKey.scalar
        .add(selfReducedX.mul(ephemeralPrivateKey.scalar))
        .mod(SM2_N)
    if (t.isZero()) {
        throw CryptoException(InvalidArgument, "SM2 key-exchange scalar is zero")
    }

    let weightedPeerEphemeral = scalarMul(peerEphemeralPublic, peerReducedX)
    let combinedPeer = pointAdd(
        Sm2Point(peerStaticPublic.x, peerStaticPublic.y),
        weightedPeerEphemeral
    )
    if (combinedPeer.infinity) {
        throw CryptoException(InvalidArgument, "SM2 key-exchange peer point is infinity")
    }
    let (sharedX, sharedY, sharedInfinity) = sm2p256v1ScalarMul(combinedPeer.x, combinedPeer.y, t)
    if (sharedInfinity) {
        throw CryptoException(InvalidArgument, "SM2 key-exchange shared point is infinity")
    }
    let shared = Sm2Point(sharedX, sharedY)

    let initiatorStatic = if (initiator) { selfStaticPublic } else { peerStaticPublic }
    let responderStatic = if (initiator) { peerStaticPublic } else { selfStaticPublic }
    let initiatorEphemeral = if (initiator) { selfEphemeralPublic } else { peerEphemeralPublic }
    let responderEphemeral = if (initiator) { peerEphemeralPublic } else { selfEphemeralPublic }
    let initiatorIdentity = if (initiator) { selfIdentity } else { peerIdentity }
    let responderIdentity = if (initiator) { peerIdentity } else { selfIdentity }
    let za = sm2ComputeZa(initiatorIdentity, initiatorStatic)
    let zb = sm2ComputeZa(responderIdentity, responderStatic)

    let keyInput = concatMany([
        shared.x.toBytesBE(paddedLen: SM2_FIELD_SIZE),
        shared.y.toBytesBE(paddedLen: SM2_FIELD_SIZE),
        za,
        zb
    ])
    let key = sm3Kdf(keyInput, keyLen)
    if (allZero(key)) {
        throw CryptoException(InvalidArgument, "SM2 key exchange derived an all-zero key")
    }

    let inner = sm3(concatMany([
        shared.x.toBytesBE(paddedLen: SM2_FIELD_SIZE),
        za,
        zb,
        initiatorEphemeral.x.toBytesBE(paddedLen: SM2_FIELD_SIZE),
        initiatorEphemeral.y.toBytesBE(paddedLen: SM2_FIELD_SIZE),
        responderEphemeral.x.toBytesBE(paddedLen: SM2_FIELD_SIZE),
        responderEphemeral.y.toBytesBE(paddedLen: SM2_FIELD_SIZE)
    ]))
    let confirmResponder = sm3(concatMany([
        [UInt8(0x02)],
        shared.y.toBytesBE(paddedLen: SM2_FIELD_SIZE),
        inner
    ]))
    let confirmInitiator = sm3(concatMany([
        [UInt8(0x03)],
        shared.y.toBytesBE(paddedLen: SM2_FIELD_SIZE),
        inner
    ]))
    if (initiator) {
        return Sm2KeyExchangeResult(key, confirmInitiator, confirmResponder)
    }
    Sm2KeyExchangeResult(key, confirmResponder, confirmInitiator)
}

private func scalarInRange(value: BigNum): Bool {
    !value.isZero() && !value.isNegative() && value.cmp(SM2_N) < 0
}

private func randomScalar(): BigNum {
    var attempt: Int64 = 0
    while (attempt < 128) {
        let candidate = BigNum.fromBytesBE(randomSeed(size: SM2_FIELD_SIZE))
        if (scalarInRange(candidate)) {
            return candidate
        }
        attempt += 1
    }
    throw CryptoException(InternalError, "SM2 scalar generation exhausted retry limit")
}

private func generatorMul(scalar: BigNum): Sm2Point {
    let (x, y, infinity) = sm2p256v1GeneratorMul(scalar)
    if (infinity) { Sm2Point.infinityPoint() } else { Sm2Point(x, y) }
}

private func scalarMul(publicKey: Sm2PublicKey, scalar: BigNum): Sm2Point {
    let (x, y, infinity) = sm2p256v1ScalarMul(publicKey.x, publicKey.y, scalar)
    if (infinity) { Sm2Point.infinityPoint() } else { Sm2Point(x, y) }
}

private func pointAdd(left: Sm2Point, right: Sm2Point): Sm2Point {
    if (left.infinity) { return right }
    if (right.infinity) { return left }
    if (left.x.cmp(right.x) == 0) {
        if (left.y.add(right.y).mod(SM2_P).isZero()) {
            return Sm2Point.infinityPoint()
        }
        return pointDouble(left)
    }
    let numerator = right.y.sub(left.y).mod(SM2_P)
    let denominator = right.x.sub(left.x).mod(SM2_P)
    let inverse = denominator.modInversePrimeFixedSchedule(SM2_P, 256)
    let lambda = numerator.mul(inverse).mod(SM2_P)
    let x = lambda.mul(lambda).sub(left.x).sub(right.x).mod(SM2_P)
    let y = lambda.mul(left.x.sub(x)).sub(left.y).mod(SM2_P)
    Sm2Point(x, y)
}

private func pointDouble(point: Sm2Point): Sm2Point {
    if (point.infinity || point.y.isZero()) {
        return Sm2Point.infinityPoint()
    }
    let numerator = BigNum.fromHex("3").mul(point.x.mul(point.x)).add(SM2_A).mod(SM2_P)
    let denominator = BigNum.fromHex("2").mul(point.y).mod(SM2_P)
    let inverse = denominator.modInversePrimeFixedSchedule(SM2_P, 256)
    let lambda = numerator.mul(inverse).mod(SM2_P)
    let x = lambda.mul(lambda).sub(point.x).sub(point.x).mod(SM2_P)
    let y = lambda.mul(point.x.sub(x)).sub(point.y).mod(SM2_P)
    Sm2Point(x, y)
}

private func pointCoordinates(point: Sm2Point): Array<Byte> {
    let output = Array<Byte>(64, repeat: UInt8(0))
    copyInto(point.x.toBytesBE(paddedLen: SM2_FIELD_SIZE), output, 0)
    copyInto(point.y.toBytesBE(paddedLen: SM2_FIELD_SIZE), output, SM2_FIELD_SIZE)
    output
}

private func xorBytes(left: Array<Byte>, right: Array<Byte>): Array<Byte> {
    let output = Array<Byte>(left.size, repeat: UInt8(0))
    var i: Int64 = 0
    while (i < left.size) {
        output[i] = left[i] ^ right[i]
        i += 1
    }
    output
}

private func allZero(value: Array<Byte>): Bool {
    var combined: UInt8 = 0
    for (byte in value) {
        combined |= byte
    }
    combined == 0
}

private func wipeBytes(value: Array<Byte>): Unit {
    var i: Int64 = 0
    while (i < value.size) {
        value[i] = UInt8(0)
        i += 1
    }
}

private func concatMany(parts: Array<Array<Byte>>): Array<Byte> {
    var size: Int64 = 0
    for (part in parts) {
        size += part.size
    }
    let output = Array<Byte>(size, repeat: UInt8(0))
    var offset: Int64 = 0
    for (part in parts) {
        copyInto(part, output, offset)
        offset += part.size
    }
    output
}

private func copyInto(input: Array<Byte>, output: Array<Byte>, offset: Int64): Unit {
    var i: Int64 = 0
    while (i < input.size) {
        output[offset + i] = input[i]
        i += 1
    }
}
