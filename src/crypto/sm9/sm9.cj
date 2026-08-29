package jinguissl_core.crypto.sm9

import std.math.numeric.BigInt
import jinguissl_core.crypto.bignum.BigNum
import jinguissl_core.crypto.error.{CryptoException, CryptoErrorCode}
import jinguissl_core.crypto.sm3.{Sm3Context, sm3, sm3Kdf}
import jinguissl_core.crypto.utils.{constantTimeEquals, csprngBytes}

public let SM9_FIELD_BYTES: Int64 = 32
public let SM9_G1_BYTES: Int64 = 64
public let SM9_G2_BYTES: Int64 = 128
public let SM9_TARGET_BYTES: Int64 = 384

private let SM9_P: BigInt = sm9Big("B640000002A3A6F1D603AB4FF58EC74521F2934B1A7AEEDBE56F9B27E351457D")
private let SM9_N: BigInt = sm9Big("B640000002A3A6F1D603AB4FF58EC74449F2934B18EA8BEEE56EE19CD69ECF25")
private let SM9_N_MINUS_ONE: BigInt = SM9_N - BigInt(1)
private let SM9_ATE_LOOP: BigInt = sm9Big("2400000000215D93E")
private let SM9_FINAL_EXPONENT: BigInt = sm9Big(
    "61835E8B12594991A09A6AE43ADE454ACEF6F4E86411255C16BE7FBACA54D38D" +
    "D9D1D3019DBA1539BF41BCB4067AA64BE8CB0476C5042CB93B5122D974B7BA19" +
    "6F691269CEB7907239E0CB2A13873665ED57CD410455806B97559B180EE9629F1" +
    "C8D7D0598EEE9B93DC562FA23AFA5A3BED65F00632C9CC80357732739295EDCB5" +
    "A6B4B9EC19BA7A4DEFA394C04689AB78BD480FF56FA0696FD3135583D5AA1335" +
    "D59C358AAC66EE2C3601D19F32C692FB14FC5412315EC5A54D51E82F7DD63455" +
    "0E98DCA2042C36B948EBD4AA170BAE804F361D729E88DC3E3945F87BF22030F4" +
    "C6983D64089BDF703B00C9E53535A5BBD6C4AA78C62F31D16182C1D978AD0EFE" +
    "915CAB1B62D11B760558913D719F2BB6793F9FE39F2568478B1A3E843D1FA0B4" +
    "8EE8FD4C31B8F6FE5E935A4B5F799CBD806A8225955B05B83E3D7E2D0B9698E" +
    "4890AB7E824DC7C6135FEC864E1676B19FE1764AC0B7482FACDD0F0D042330"
)

private let SM9_P1_X: BigInt = sm9Big("93DE051D62BF718FF5ED0704487D01D6E1E4086909DC3280E8C4E4817C66DDDD")
private let SM9_P1_Y: BigInt = sm9Big("21FE8DDA4F21E607631065125C395BBC1C1C00CBFA6024350C464CD70A3EA616")
private let SM9_P2_X0: BigInt = sm9Big("3722755292130B08D2AAB97FD34EC120EE265948D19C17ABF9B7213BAF82D65B")
private let SM9_P2_X1: BigInt = sm9Big("85AEF3D078640C98597B6027B441A01FF1DD2C190F5E93C454806C11D8806141")
private let SM9_P2_Y0: BigInt = sm9Big("A7CF28D519BE3DA65F3170153D278FF247EFBA98A71A08116215BBA5C999A7C7")
private let SM9_P2_Y1: BigInt = sm9Big("17509B092E845C1266BA0D262CBEE6ED0736A96FA347C8BD856DC76B84EBEB96")

/** A validated point in the SM9 G1 group. */
public class Sm9G1Point {
    public let x: BigNum
    public let y: BigNum

    public init(x: BigNum, y: BigNum) {
        if (!sm9CanonicalFieldElement(x.toBigInt()) || !sm9CanonicalFieldElement(y.toBigInt())) {
            throw CryptoException(InvalidArgument, "SM9 G1 coordinates must be canonical field elements")
        }
        let point = Sm9G1(x.toBigInt(), y.toBigInt())
        if (!sm9G1OnCurve(point)) {
            throw CryptoException(InvalidArgument, "SM9 G1 point is not on the standard curve")
        }
        this.x = BigNum(point.x)
        this.y = BigNum(point.y)
    }
}

/** A validated point in the SM9 G2 twist; coefficients are c0 + c1*u. */
public class Sm9G2Point {
    public let x0: BigNum
    public let x1: BigNum
    public let y0: BigNum
    public let y1: BigNum

    public init(x0: BigNum, x1: BigNum, y0: BigNum, y1: BigNum) {
        if (
            !sm9CanonicalFieldElement(x0.toBigInt()) ||
            !sm9CanonicalFieldElement(x1.toBigInt()) ||
            !sm9CanonicalFieldElement(y0.toBigInt()) ||
            !sm9CanonicalFieldElement(y1.toBigInt())
        ) {
            throw CryptoException(InvalidArgument, "SM9 G2 coordinates must be canonical field elements")
        }
        let point = Sm9G2(
            Sm9Fp2(x0.toBigInt(), x1.toBigInt()),
            Sm9Fp2(y0.toBigInt(), y1.toBigInt())
        )
        if (!sm9G2OnCurve(point)) {
            throw CryptoException(InvalidArgument, "SM9 G2 point is not on the standard twist")
        }
        if (!sm9G2Mul(point, SM9_N).infinity) {
            throw CryptoException(InvalidArgument, "SM9 G2 point is outside the prime-order subgroup")
        }
        this.x0 = BigNum(point.x.a)
        this.x1 = BigNum(point.x.b)
        this.y0 = BigNum(point.y.a)
        this.y1 = BigNum(point.y.b)
    }
}

/** An immutable SM9 target-group element encoded in the standard 384-byte order. */
public class Sm9TargetElement {
    private let encoded: Array<Byte>

    internal init(encoded: Array<Byte>) {
        if (encoded.size != SM9_TARGET_BYTES) {
            throw CryptoException(InvalidArgument, "SM9 target element must be 384 bytes")
        }
        this.encoded = encoded.clone()
    }

    public func toBytes(): Array<Byte> { encoded.clone() }
}

/** A validated SM9 signature encoded as h || S.x || S.y. */
public class Sm9Signature {
    public let h: BigNum
    public let point: Sm9G1Point

    public init(h: BigNum, point: Sm9G1Point) {
        if (!sm9ScalarInRange(h.toBigInt())) {
            throw CryptoException(InvalidArgument, "SM9 signature h must be in [1, n-1]")
        }
        this.h = h
        this.point = point
    }

    public func toBytes(): Array<Byte> {
        sm9Concat([
            h.toBytesBE(paddedLen: SM9_FIELD_BYTES),
            sm9G1PointToBytes(point)
        ])
    }

    public static func fromBytes(encoded: Array<Byte>): Sm9Signature {
        if (encoded.size != SM9_FIELD_BYTES + SM9_G1_BYTES) {
            throw CryptoException(ParseError, "SM9 signature must be 96 bytes")
        }
        Sm9Signature(
            BigNum.fromBytesBE(encoded[..SM9_FIELD_BYTES]),
            sm9G1PointFromBytes(encoded[SM9_FIELD_BYTES..])
        )
    }
}

/** KGC signing master private scalar. */
public class Sm9SignMasterPrivateKey {
    public let scalar: BigNum

    public init(scalar: BigNum) {
        if (!sm9ScalarInRange(scalar.toBigInt())) {
            throw CryptoException(InvalidArgument, "SM9 signing master scalar must be in [1, n-1]")
        }
        this.scalar = scalar
    }
}

/** KGC signing master public point in G2. */
public class Sm9SignMasterPublicKey {
    public let point: Sm9G2Point
    public init(point: Sm9G2Point) { this.point = point }
}

/** Identity-bound signing private point in G1. */
public class Sm9SignUserPrivateKey {
    public let point: Sm9G1Point
    public let masterPublicKey: Sm9SignMasterPublicKey

    public init(point: Sm9G1Point, masterPublicKey: Sm9SignMasterPublicKey) {
        this.point = point
        this.masterPublicKey = masterPublicKey
    }
}

/** KGC encryption/key-exchange master private scalar. */
public class Sm9EncryptionMasterPrivateKey {
    public let scalar: BigNum

    public init(scalar: BigNum) {
        if (!sm9ScalarInRange(scalar.toBigInt())) {
            throw CryptoException(InvalidArgument, "SM9 encryption master scalar must be in [1, n-1]")
        }
        this.scalar = scalar
    }
}

/** KGC encryption/key-exchange master public point in G1. */
public class Sm9EncryptionMasterPublicKey {
    public let point: Sm9G1Point
    public init(point: Sm9G1Point) { this.point = point }
}

/** Identity-bound encryption/key-exchange private point in G2. */
public class Sm9EncryptionUserPrivateKey {
    public let point: Sm9G2Point
    public let masterPublicKey: Sm9EncryptionMasterPublicKey

    public init(point: Sm9G2Point, masterPublicKey: Sm9EncryptionMasterPublicKey) {
        this.point = point
        this.masterPublicKey = masterPublicKey
    }
}

/** One side's retained ephemeral state for the SM9 key exchange. */
public class Sm9KeyExchangeState {
    internal let userPrivateKey: Sm9EncryptionUserPrivateKey
    internal let selfIdentity: Array<Byte>
    internal let peerIdentity: Array<Byte>
    internal let hierarchy: Byte
    internal let scalar: BigInt
    public let ephemeralPublic: Sm9G1Point

    internal init(
        userPrivateKey: Sm9EncryptionUserPrivateKey,
        selfIdentity: Array<Byte>,
        peerIdentity: Array<Byte>,
        hierarchy: Byte,
        scalar: BigInt,
        ephemeralPublic: Sm9G1Point
    ) {
        this.userPrivateKey = userPrivateKey
        this.selfIdentity = selfIdentity.clone()
        this.peerIdentity = peerIdentity.clone()
        this.hierarchy = hierarchy
        this.scalar = scalar
        this.ephemeralPublic = ephemeralPublic
    }
}

/** Derived key and the role-specific confirmation values. */
public class Sm9KeyExchangeResult {
    public let key: Array<Byte>
    public let sendConfirmation: Array<Byte>
    public let expectedPeerConfirmation: Array<Byte>

    public init(
        key: Array<Byte>,
        sendConfirmation: Array<Byte>,
        expectedPeerConfirmation: Array<Byte>
    ) {
        this.key = key.clone()
        this.sendConfirmation = sendConfirmation.clone()
        this.expectedPeerConfirmation = expectedPeerConfirmation.clone()
    }
}

/** Return the standard SM9 generator P1. */
public func sm9GeneratorG1(): Sm9G1Point {
    Sm9G1Point(BigNum(SM9_P1_X), BigNum(SM9_P1_Y))
}

/** Return the standard SM9 twist generator P2. */
public func sm9GeneratorG2(): Sm9G2Point {
    Sm9G2Point(
        BigNum(SM9_P2_X0), BigNum(SM9_P2_X1),
        BigNum(SM9_P2_Y0), BigNum(SM9_P2_Y1)
    )
}

/** Encode a G1 point as x || y. */
public func sm9G1PointToBytes(point: Sm9G1Point): Array<Byte> {
    let output = Array<Byte>(SM9_G1_BYTES, repeat: UInt8(0))
    sm9Copy(point.x.toBytesBE(paddedLen: SM9_FIELD_BYTES), output, 0)
    sm9Copy(point.y.toBytesBE(paddedLen: SM9_FIELD_BYTES), output, SM9_FIELD_BYTES)
    output
}

/** Decode and validate an x || y G1 point. */
public func sm9G1PointFromBytes(encoded: Array<Byte>): Sm9G1Point {
    if (encoded.size != SM9_G1_BYTES) {
        throw CryptoException(ParseError, "SM9 G1 encoding must be 64 bytes")
    }
    Sm9G1Point(
        BigNum.fromBytesBE(encoded[..SM9_FIELD_BYTES]),
        BigNum.fromBytesBE(encoded[SM9_FIELD_BYTES..])
    )
}

/** Encode a G2 point as x1 || x0 || y1 || y0. */
public func sm9G2PointToBytes(point: Sm9G2Point): Array<Byte> {
    let output = Array<Byte>(SM9_G2_BYTES, repeat: UInt8(0))
    sm9Copy(point.x1.toBytesBE(paddedLen: SM9_FIELD_BYTES), output, 0)
    sm9Copy(point.x0.toBytesBE(paddedLen: SM9_FIELD_BYTES), output, 32)
    sm9Copy(point.y1.toBytesBE(paddedLen: SM9_FIELD_BYTES), output, 64)
    sm9Copy(point.y0.toBytesBE(paddedLen: SM9_FIELD_BYTES), output, 96)
    output
}

/** Decode, curve-check and subgroup-check an x1 || x0 || y1 || y0 G2 point. */
public func sm9G2PointFromBytes(encoded: Array<Byte>): Sm9G2Point {
    if (encoded.size != SM9_G2_BYTES) {
        throw CryptoException(ParseError, "SM9 G2 encoding must be 128 bytes")
    }
    Sm9G2Point(
        BigNum.fromBytesBE(encoded[32..64]),
        BigNum.fromBytesBE(encoded[..32]),
        BigNum.fromBytesBE(encoded[96..128]),
        BigNum.fromBytesBE(encoded[64..96])
    )
}

/** Compute the standard R-ate pairing e(P, Q). */
public func sm9Pairing(pointG1: Sm9G1Point, pointG2: Sm9G2Point): Sm9TargetElement {
    Sm9TargetElement(sm9Fp12ToBytes(sm9Pair(sm9G1Internal(pointG1), sm9G2Internal(pointG2))))
}

/** Compute the SM9 H1 identity hash in [1, n-1]. */
public func sm9HashH1(input: Array<Byte>): BigNum { BigNum(sm9HashToScalar(UInt8(0x01), input)) }

/** Compute the SM9 H2 message/target hash in [1, n-1]. */
public func sm9HashH2(input: Array<Byte>): BigNum { BigNum(sm9HashToScalar(UInt8(0x02), input)) }

/** Generate a signing master private key with the runtime CSPRNG. */
public func sm9GenerateSignMasterPrivateKey(): Sm9SignMasterPrivateKey {
    Sm9SignMasterPrivateKey(BigNum(sm9RandomScalar()))
}

/** Derive the signing master public key Ppub-s = [ks]P2. */
public func sm9SignMasterPublicKey(privateKey: Sm9SignMasterPrivateKey): Sm9SignMasterPublicKey {
    let point = sm9G2Mul(sm9StandardG2(), privateKey.scalar.toBigInt())
    Sm9SignMasterPublicKey(sm9PublicG2(point))
}

/** Extract the identity-bound signing private key ds. */
public func sm9ExtractSignUserPrivateKey(
    masterPrivateKey: Sm9SignMasterPrivateKey,
    identity: Array<Byte>,
    hierarchy!: Byte = UInt8(0x01)
): Sm9SignUserPrivateKey {
    sm9ValidateIdentity(identity)
    let h1 = sm9IdentityHash(identity, hierarchy)
    let denominator = sm9ModN(h1 + masterPrivateKey.scalar.toBigInt())
    if (denominator == BigInt(0)) {
        throw CryptoException(InvalidArgument, "SM9 signing master key is invalid for this identity")
    }
    let factor = sm9ModN(masterPrivateKey.scalar.toBigInt() * sm9InverseN(denominator))
    let point = sm9G1Mul(sm9StandardG1(), factor)
    Sm9SignUserPrivateKey(sm9PublicG1(point), sm9SignMasterPublicKey(masterPrivateKey))
}

/** Sign a message with a fresh CSPRNG nonce. */
public func sm9Sign(userPrivateKey: Sm9SignUserPrivateKey, message: Array<Byte>): Sm9Signature {
    var attempt: Int64 = 0
    while (attempt < 128) {
        let nonce = BigNum(sm9RandomScalar())
        try {
            return sm9SignWithNonce(userPrivateKey, message, nonce)
        } catch (error: CryptoException) {
            if (error.message != "SM9 signing nonce produced a zero response") {
                throw error
            }
        }
        attempt += 1
    }
    throw CryptoException(InternalError, "SM9 signing exhausted the nonce retry limit")
}

/** Sign with an explicit nonce for published-vector replay. */
public func sm9SignWithNonce(
    userPrivateKey: Sm9SignUserPrivateKey,
    message: Array<Byte>,
    nonce: BigNum
): Sm9Signature {
    if (!sm9ScalarInRange(nonce.toBigInt())) {
        throw CryptoException(InvalidArgument, "SM9 signing nonce must be in [1, n-1]")
    }
    let masterPoint = sm9G2Internal(userPrivateKey.masterPublicKey.point)
    let base = sm9Pair(sm9StandardG1(), masterPoint)
    let w = sm9Fp12Pow(base, nonce.toBigInt())
    let h = sm9HashToScalar(UInt8(0x02), sm9Concat([message, sm9Fp12ToBytes(w)]))
    let l = sm9ModN(nonce.toBigInt() - h)
    if (l == BigInt(0)) {
        throw CryptoException(InvalidArgument, "SM9 signing nonce produced a zero response")
    }
    let point = sm9G1Mul(sm9G1Internal(userPrivateKey.point), l)
    Sm9Signature(BigNum(h), sm9PublicG1(point))
}

/** Verify an identity-bound SM9 signature. */
public func sm9Verify(
    masterPublicKey: Sm9SignMasterPublicKey,
    identity: Array<Byte>,
    message: Array<Byte>,
    signature: Sm9Signature,
    hierarchy!: Byte = UInt8(0x01)
): Bool {
    try {
        sm9ValidateIdentity(identity)
        let h = signature.h.toBigInt()
        if (!sm9ScalarInRange(h)) { return false }
        let base = sm9Pair(sm9StandardG1(), sm9G2Internal(masterPublicKey.point))
        let t = sm9Fp12Pow(base, h)
        let h1 = sm9IdentityHash(identity, hierarchy)
        let publicForIdentity = sm9G2Add(
            sm9G2Mul(sm9StandardG2(), h1),
            sm9G2Internal(masterPublicKey.point)
        )
        if (publicForIdentity.infinity) { return false }
        let u = sm9Pair(sm9G1Internal(signature.point), publicForIdentity)
        let w = sm9Fp12Mul(t, u)
        let expected = sm9HashToScalar(UInt8(0x02), sm9Concat([message, sm9Fp12ToBytes(w)]))
        expected == h
    } catch (_: Exception) {
        false
    }
}

/** Generate an encryption/key-exchange master private key with the runtime CSPRNG. */
public func sm9GenerateEncryptionMasterPrivateKey(): Sm9EncryptionMasterPrivateKey {
    Sm9EncryptionMasterPrivateKey(BigNum(sm9RandomScalar()))
}

/** Derive the encryption master public key Ppub-e = [ke]P1. */
public func sm9EncryptionMasterPublicKey(
    privateKey: Sm9EncryptionMasterPrivateKey
): Sm9EncryptionMasterPublicKey {
    Sm9EncryptionMasterPublicKey(sm9PublicG1(sm9G1Mul(sm9StandardG1(), privateKey.scalar.toBigInt())))
}

/** Extract the identity-bound encryption/key-exchange private key de. */
public func sm9ExtractEncryptionUserPrivateKey(
    masterPrivateKey: Sm9EncryptionMasterPrivateKey,
    identity: Array<Byte>,
    hierarchy!: Byte = UInt8(0x03)
): Sm9EncryptionUserPrivateKey {
    sm9ValidateIdentity(identity)
    let h1 = sm9IdentityHash(identity, hierarchy)
    let denominator = sm9ModN(h1 + masterPrivateKey.scalar.toBigInt())
    if (denominator == BigInt(0)) {
        throw CryptoException(InvalidArgument, "SM9 encryption master key is invalid for this identity")
    }
    let factor = sm9ModN(masterPrivateKey.scalar.toBigInt() * sm9InverseN(denominator))
    let point = sm9G2Mul(sm9StandardG2(), factor)
    Sm9EncryptionUserPrivateKey(
        sm9PublicG2(point),
        sm9EncryptionMasterPublicKey(masterPrivateKey)
    )
}

/** Encrypt as the standard raw C1 || C3 || C2 profile. */
public func sm9Encrypt(
    masterPublicKey: Sm9EncryptionMasterPublicKey,
    identity: Array<Byte>,
    plaintext: Array<Byte>,
    hierarchy!: Byte = UInt8(0x03)
): Array<Byte> {
    sm9ValidateIdentity(identity)
    if (plaintext.size == 0) {
        throw CryptoException(InvalidArgument, "SM9 plaintext must not be empty")
    }
    var attempt: Int64 = 0
    while (attempt < 128) {
        let nonce = BigNum(sm9RandomScalar())
        try {
            return sm9EncryptWithNonce(
                masterPublicKey, identity, plaintext, nonce, hierarchy: hierarchy
            )
        } catch (error: CryptoException) {
            if (error.message != "SM9 encryption derived an all-zero mask") {
                throw error
            }
        }
        attempt += 1
    }
    throw CryptoException(InternalError, "SM9 encryption exhausted the nonce retry limit")
}

/** Encrypt with an explicit nonce for published-vector replay. */
public func sm9EncryptWithNonce(
    masterPublicKey: Sm9EncryptionMasterPublicKey,
    identity: Array<Byte>,
    plaintext: Array<Byte>,
    nonce: BigNum,
    hierarchy!: Byte = UInt8(0x03)
): Array<Byte> {
    sm9ValidateIdentity(identity)
    if (plaintext.size == 0) {
        throw CryptoException(InvalidArgument, "SM9 plaintext must not be empty")
    }
    if (!sm9ScalarInRange(nonce.toBigInt())) {
        throw CryptoException(InvalidArgument, "SM9 encryption nonce must be in [1, n-1]")
    }
    let h1 = sm9IdentityHash(identity, hierarchy)
    let q = sm9G1Add(
        sm9G1Mul(sm9StandardG1(), h1),
        sm9G1Internal(masterPublicKey.point)
    )
    if (q.infinity) {
        throw CryptoException(InvalidArgument, "SM9 identity public point is infinity")
    }
    let c1 = sm9G1Mul(q, nonce.toBigInt())
    let base = sm9Pair(sm9G1Internal(masterPublicKey.point), sm9StandardG2())
    let w = sm9Fp12Pow(base, nonce.toBigInt())
    let c1Bytes = sm9G1ToBytes(c1)
    let key = sm3Kdf(
        sm9Concat([c1Bytes, sm9Fp12ToBytes(w), identity]),
        plaintext.size + 32
    )
    let mask = key[..plaintext.size]
    if (sm9AllZero(mask)) {
        throw CryptoException(InvalidArgument, "SM9 encryption derived an all-zero mask")
    }
    let c2 = sm9Xor(plaintext, mask)
    let c3 = sm3(sm9Concat([c2, key[plaintext.size..]]))
    sm9Concat([c1Bytes, c3, c2])
}

/** Decrypt raw C1 || C3 || C2 and authenticate C3 before releasing plaintext. */
public func sm9Decrypt(
    userPrivateKey: Sm9EncryptionUserPrivateKey,
    identity: Array<Byte>,
    ciphertext: Array<Byte>
): Array<Byte> {
    sm9ValidateIdentity(identity)
    if (ciphertext.size <= SM9_G1_BYTES + 32) {
        throw CryptoException(ParseError, "SM9 ciphertext is too short")
    }
    let c1Bytes = ciphertext[..SM9_G1_BYTES]
    let c1 = sm9G1PointFromBytes(c1Bytes)
    let c3 = ciphertext[SM9_G1_BYTES..SM9_G1_BYTES + 32]
    let c2 = ciphertext[SM9_G1_BYTES + 32..]
    let w = sm9Pair(sm9G1Internal(c1), sm9G2Internal(userPrivateKey.point))
    let key = sm3Kdf(sm9Concat([c1Bytes, sm9Fp12ToBytes(w), identity]), c2.size + 32)
    let mask = key[..c2.size]
    if (sm9AllZero(mask)) {
        throw CryptoException(InvalidArgument, "SM9 decryption derived an all-zero mask")
    }
    let expected = sm3(sm9Concat([c2, key[c2.size..]]))
    if (!constantTimeEquals(expected, c3)) {
        throw CryptoException(InvalidArgument, "SM9 ciphertext authentication failed")
    }
    sm9Xor(c2, mask)
}

/** Begin one SM9 key-exchange side with a fresh CSPRNG scalar. */
public func sm9BeginKeyExchange(
    userPrivateKey: Sm9EncryptionUserPrivateKey,
    selfIdentity: Array<Byte>,
    peerIdentity: Array<Byte>,
    hierarchy!: Byte = UInt8(0x02)
): Sm9KeyExchangeState {
    sm9BeginKeyExchangeWithNonce(
        userPrivateKey, selfIdentity, peerIdentity, BigNum(sm9RandomScalar()), hierarchy: hierarchy
    )
}

/** Begin one SM9 key-exchange side with an explicit scalar for vector replay. */
public func sm9BeginKeyExchangeWithNonce(
    userPrivateKey: Sm9EncryptionUserPrivateKey,
    selfIdentity: Array<Byte>,
    peerIdentity: Array<Byte>,
    nonce: BigNum,
    hierarchy!: Byte = UInt8(0x02)
): Sm9KeyExchangeState {
    sm9ValidateIdentity(selfIdentity)
    sm9ValidateIdentity(peerIdentity)
    if (!sm9ScalarInRange(nonce.toBigInt())) {
        throw CryptoException(InvalidArgument, "SM9 key-exchange scalar must be in [1, n-1]")
    }
    let h1 = sm9IdentityHash(peerIdentity, hierarchy)
    let peerPublic = sm9G1Add(
        sm9G1Mul(sm9StandardG1(), h1),
        sm9G1Internal(userPrivateKey.masterPublicKey.point)
    )
    if (peerPublic.infinity) {
        throw CryptoException(InvalidArgument, "SM9 peer identity public point is infinity")
    }
    let ephemeral = sm9G1Mul(peerPublic, nonce.toBigInt())
    Sm9KeyExchangeState(
        userPrivateKey,
        selfIdentity,
        peerIdentity,
        hierarchy,
        nonce.toBigInt(),
        sm9PublicG1(ephemeral)
    )
}

/** Complete either role of the authenticated SM9 key exchange. */
public func sm9CompleteKeyExchange(
    state: Sm9KeyExchangeState,
    peerEphemeralPublic: Sm9G1Point,
    initiator: Bool,
    keyLen: Int64
): Sm9KeyExchangeResult {
    if (keyLen <= 0) {
        throw CryptoException(InvalidArgument, "SM9 key-exchange output length must be positive")
    }
    let masterPublic = sm9G1Internal(state.userPrivateKey.masterPublicKey.point)
    let base = sm9Pair(masterPublic, sm9StandardG2())
    let selfPower = sm9Fp12Pow(base, state.scalar)
    let peerPair = sm9Pair(
        sm9G1Internal(peerEphemeralPublic),
        sm9G2Internal(state.userPrivateKey.point)
    )
    let g1 = if (initiator) { selfPower } else { peerPair }
    let g2 = if (initiator) { peerPair } else { selfPower }
    let g3 = if (initiator) {
        sm9Fp12Pow(g2, state.scalar)
    } else {
        sm9Fp12Pow(g1, state.scalar)
    }

    let initiatorIdentity = if (initiator) { state.selfIdentity } else { state.peerIdentity }
    let responderIdentity = if (initiator) { state.peerIdentity } else { state.selfIdentity }
    let initiatorPoint = if (initiator) { state.ephemeralPublic } else { peerEphemeralPublic }
    let responderPoint = if (initiator) { peerEphemeralPublic } else { state.ephemeralPublic }
    let initiatorBytes = sm9G1PointToBytes(initiatorPoint)
    let responderBytes = sm9G1PointToBytes(responderPoint)
    let g1Bytes = sm9Fp12ToBytes(g1)
    let g2Bytes = sm9Fp12ToBytes(g2)
    let g3Bytes = sm9Fp12ToBytes(g3)

    let key = sm3Kdf(sm9Concat([
        initiatorIdentity, responderIdentity,
        initiatorBytes, responderBytes,
        g1Bytes, g2Bytes, g3Bytes
    ]), keyLen)
    if (sm9AllZero(key)) {
        throw CryptoException(InvalidArgument, "SM9 key exchange derived an all-zero key")
    }
    let inner = sm3(sm9Concat([
        g2Bytes, g3Bytes,
        initiatorIdentity, responderIdentity,
        initiatorBytes, responderBytes
    ]))
    let responderConfirmation = sm3(sm9Concat([[UInt8(0x82)], g1Bytes, inner]))
    let initiatorConfirmation = sm3(sm9Concat([[UInt8(0x83)], g1Bytes, inner]))
    if (initiator) {
        return Sm9KeyExchangeResult(key, initiatorConfirmation, responderConfirmation)
    }
    Sm9KeyExchangeResult(key, responderConfirmation, initiatorConfirmation)
}

/** Compare a received key-exchange confirmation without an early byte exit. */
public func sm9VerifyKeyExchangeConfirmation(
    expected: Array<Byte>, received: Array<Byte>
): Bool {
    expected.size == 32 && received.size == 32 && constantTimeEquals(expected, received)
}

private class Sm9Fp2 {
    let a: BigInt
    let b: BigInt
    init(a: BigInt, b: BigInt) { this.a = sm9ModP(a); this.b = sm9ModP(b) }
}

private class Sm9Fp4 {
    let a: Sm9Fp2
    let b: Sm9Fp2
    init(a: Sm9Fp2, b: Sm9Fp2) { this.a = a; this.b = b }
}

private class Sm9Fp12 {
    let a: Sm9Fp4
    let b: Sm9Fp4
    let c: Sm9Fp4
    init(a: Sm9Fp4, b: Sm9Fp4, c: Sm9Fp4) { this.a = a; this.b = b; this.c = c }
}

private class Sm9G1 {
    let x: BigInt
    let y: BigInt
    let infinity: Bool
    init(x: BigInt, y: BigInt, infinity!: Bool = false) {
        this.x = sm9ModP(x); this.y = sm9ModP(y); this.infinity = infinity
    }
}

private class Sm9G2 {
    let x: Sm9Fp2
    let y: Sm9Fp2
    let infinity: Bool
    init(x: Sm9Fp2, y: Sm9Fp2, infinity!: Bool = false) {
        this.x = x; this.y = y; this.infinity = infinity
    }
}

private class Sm9FullPoint {
    let x: Sm9Fp12
    let y: Sm9Fp12
    init(x: Sm9Fp12, y: Sm9Fp12) { this.x = x; this.y = y }
}

private class Sm9LineStep {
    let point: Sm9FullPoint
    let line: Sm9Fp12
    init(point: Sm9FullPoint, line: Sm9Fp12) { this.point = point; this.line = line }
}

private func sm9StandardG1(): Sm9G1 { Sm9G1(SM9_P1_X, SM9_P1_Y) }
private func sm9StandardG2(): Sm9G2 {
    Sm9G2(
        Sm9Fp2(SM9_P2_X0, SM9_P2_X1),
        Sm9Fp2(SM9_P2_Y0, SM9_P2_Y1)
    )
}

private func sm9PublicG1(point: Sm9G1): Sm9G1Point {
    if (point.infinity) {
        throw CryptoException(InvalidArgument, "SM9 G1 result is infinity")
    }
    Sm9G1Point(BigNum(point.x), BigNum(point.y))
}

private func sm9PublicG2(point: Sm9G2): Sm9G2Point {
    if (point.infinity) {
        throw CryptoException(InvalidArgument, "SM9 G2 result is infinity")
    }
    Sm9G2Point(
        BigNum(point.x.a), BigNum(point.x.b),
        BigNum(point.y.a), BigNum(point.y.b)
    )
}

private func sm9G1Infinity(): Sm9G1 { Sm9G1(BigInt(0), BigInt(0), infinity: true) }

private func sm9G1Add(left: Sm9G1, right: Sm9G1): Sm9G1 {
    if (left.infinity) { return right }
    if (right.infinity) { return left }
    if (left.x == right.x) {
        if (left.y != right.y || left.y == BigInt(0)) { return sm9G1Infinity() }
    }
    let lambda = if (left.x == right.x) {
        sm9ModP(BigInt(3) * left.x * left.x * sm9InverseP(BigInt(2) * left.y))
    } else {
        sm9ModP((right.y - left.y) * sm9InverseP(right.x - left.x))
    }
    let x = sm9ModP(lambda * lambda - left.x - right.x)
    let y = sm9ModP(lambda * (left.x - x) - left.y)
    Sm9G1(x, y)
}

private func sm9G1Mul(point: Sm9G1, scalar: BigInt): Sm9G1 {
    var result = sm9G1Infinity()
    var addend = point
    var remaining = sm9ModN(scalar)
    let one = BigInt(1)
    while (remaining > BigInt(0)) {
        if ((remaining & one) != BigInt(0)) { result = sm9G1Add(result, addend) }
        addend = sm9G1Add(addend, addend)
        remaining = remaining >> 1
    }
    result
}

private func sm9G1ToBytes(point: Sm9G1): Array<Byte> {
    if (point.infinity) {
        throw CryptoException(InvalidArgument, "SM9 G1 infinity has no raw encoding")
    }
    sm9Concat([
        BigNum(point.x).toBytesBE(paddedLen: SM9_FIELD_BYTES),
        BigNum(point.y).toBytesBE(paddedLen: SM9_FIELD_BYTES)
    ])
}

private func sm9HashToScalar(mode: Byte, input: Array<Byte>): BigInt {
    let first = Sm3Context()
    first.update([mode])
    first.update(input)
    first.update([UInt8(0), UInt8(0), UInt8(0), UInt8(1)])
    let second = Sm3Context()
    second.update([mode])
    second.update(input)
    second.update([UInt8(0), UInt8(0), UInt8(0), UInt8(2)])
    let expanded = sm9Concat([first.finish(), second.finish()])
    let ha = BigNum.fromBytesBE(expanded[..40]).toBigInt()
    (ha % SM9_N_MINUS_ONE) + BigInt(1)
}

private func sm9IdentityHash(identity: Array<Byte>, hierarchy: Byte): BigInt {
    sm9HashToScalar(UInt8(0x01), sm9Concat([identity, [hierarchy]]))
}

private func sm9ValidateIdentity(identity: Array<Byte>): Unit {
    if (identity.size == 0 || identity.size > 256) {
        throw CryptoException(InvalidArgument, "SM9 identity length must be in [1, 256] bytes")
    }
}

private func sm9RandomScalar(): BigInt {
    var attempt: Int64 = 0
    while (attempt < 128) {
        let candidate = BigNum.fromBytesBE(csprngBytes(SM9_FIELD_BYTES)).toBigInt()
        if (sm9ScalarInRange(candidate)) { return candidate }
        attempt += 1
    }
    throw CryptoException(InternalError, "SM9 scalar generation exhausted the retry limit")
}

private func sm9ScalarInRange(value: BigInt): Bool {
    value > BigInt(0) && value < SM9_N
}

private func sm9CanonicalFieldElement(value: BigInt): Bool {
    value >= BigInt(0) && value < SM9_P
}

private func sm9ModN(value: BigInt): BigInt {
    var reduced = value % SM9_N
    if (reduced.sign < 0) { reduced += SM9_N }
    reduced
}

private func sm9InverseN(value: BigInt): BigInt {
    let normalized = sm9ModN(value)
    if (normalized == BigInt(0)) {
        throw CryptoException(InvalidArgument, "SM9 scalar inverse does not exist")
    }
    try {
        return sm9ModN(normalized.modInverse(SM9_N))
    } catch (_: Exception) {
        throw CryptoException(InvalidArgument, "SM9 scalar inverse failed")
    }
}

private func sm9Concat(parts: Array<Array<Byte>>): Array<Byte> {
    var size: Int64 = 0
    for (part in parts) { size += part.size }
    let output = Array<Byte>(size, repeat: UInt8(0))
    var offset: Int64 = 0
    for (part in parts) {
        sm9Copy(part, output, offset)
        offset += part.size
    }
    output
}

private func sm9Xor(left: Array<Byte>, right: Array<Byte>): Array<Byte> {
    let output = Array<Byte>(left.size, repeat: UInt8(0))
    var i: Int64 = 0
    while (i < left.size) {
        output[i] = left[i] ^ right[i]
        i += 1
    }
    output
}

private func sm9AllZero(value: Array<Byte>): Bool {
    var combined: UInt8 = 0
    for (byte in value) { combined |= byte }
    combined == UInt8(0)
}

private func sm9Fp2Zero(): Sm9Fp2 { Sm9Fp2(BigInt(0), BigInt(0)) }
private func sm9Fp2One(): Sm9Fp2 { Sm9Fp2(BigInt(1), BigInt(0)) }
private func sm9Fp2Add(x: Sm9Fp2, y: Sm9Fp2): Sm9Fp2 { Sm9Fp2(x.a + y.a, x.b + y.b) }
private func sm9Fp2Neg(x: Sm9Fp2): Sm9Fp2 { Sm9Fp2(-x.a, -x.b) }
private func sm9Fp2Sub(x: Sm9Fp2, y: Sm9Fp2): Sm9Fp2 { sm9Fp2Add(x, sm9Fp2Neg(y)) }
private func sm9Fp2Mul(x: Sm9Fp2, y: Sm9Fp2): Sm9Fp2 {
    Sm9Fp2(x.a * y.a - BigInt(2) * x.b * y.b, x.a * y.b + x.b * y.a)
}
private func sm9Fp2Inverse(x: Sm9Fp2): Sm9Fp2 {
    let denominator = sm9ModP(x.a * x.a + BigInt(2) * x.b * x.b)
    let inverse = sm9InverseP(denominator)
    Sm9Fp2(x.a * inverse, -x.b * inverse)
}
private func sm9Fp2Equal(x: Sm9Fp2, y: Sm9Fp2): Bool { x.a == y.a && x.b == y.b }
private func sm9Fp2IsZero(x: Sm9Fp2): Bool { x.a == BigInt(0) && x.b == BigInt(0) }
private func sm9Fp2MulU(x: Sm9Fp2): Sm9Fp2 { Sm9Fp2(-BigInt(2) * x.b, x.a) }

private func sm9Fp4Zero(): Sm9Fp4 { Sm9Fp4(sm9Fp2Zero(), sm9Fp2Zero()) }
private func sm9Fp4One(): Sm9Fp4 { Sm9Fp4(sm9Fp2One(), sm9Fp2Zero()) }
private func sm9Fp4Add(x: Sm9Fp4, y: Sm9Fp4): Sm9Fp4 {
    Sm9Fp4(sm9Fp2Add(x.a, y.a), sm9Fp2Add(x.b, y.b))
}
private func sm9Fp4Neg(x: Sm9Fp4): Sm9Fp4 { Sm9Fp4(sm9Fp2Neg(x.a), sm9Fp2Neg(x.b)) }
private func sm9Fp4Sub(x: Sm9Fp4, y: Sm9Fp4): Sm9Fp4 { sm9Fp4Add(x, sm9Fp4Neg(y)) }
private func sm9Fp4MulV(x: Sm9Fp4): Sm9Fp4 { Sm9Fp4(sm9Fp2MulU(x.b), x.a) }
private func sm9Fp4Mul(x: Sm9Fp4, y: Sm9Fp4): Sm9Fp4 {
    Sm9Fp4(
        sm9Fp2Add(sm9Fp2Mul(x.a, y.a), sm9Fp2MulU(sm9Fp2Mul(x.b, y.b))),
        sm9Fp2Add(sm9Fp2Mul(x.a, y.b), sm9Fp2Mul(x.b, y.a))
    )
}
private func sm9Fp4Inverse(x: Sm9Fp4): Sm9Fp4 {
    let denominator = sm9Fp2Sub(sm9Fp2Mul(x.a, x.a), sm9Fp2MulU(sm9Fp2Mul(x.b, x.b)))
    let inverse = sm9Fp2Inverse(denominator)
    Sm9Fp4(sm9Fp2Mul(x.a, inverse), sm9Fp2Mul(sm9Fp2Neg(x.b), inverse))
}

private func sm9Fp12Zero(): Sm9Fp12 { Sm9Fp12(sm9Fp4Zero(), sm9Fp4Zero(), sm9Fp4Zero()) }
private func sm9Fp12One(): Sm9Fp12 { Sm9Fp12(sm9Fp4One(), sm9Fp4Zero(), sm9Fp4Zero()) }
private func sm9Fp12Embed(value: BigInt): Sm9Fp12 {
    Sm9Fp12(Sm9Fp4(Sm9Fp2(value, BigInt(0)), sm9Fp2Zero()), sm9Fp4Zero(), sm9Fp4Zero())
}
private func sm9Fp12Add(x: Sm9Fp12, y: Sm9Fp12): Sm9Fp12 {
    Sm9Fp12(sm9Fp4Add(x.a, y.a), sm9Fp4Add(x.b, y.b), sm9Fp4Add(x.c, y.c))
}
private func sm9Fp12Neg(x: Sm9Fp12): Sm9Fp12 {
    Sm9Fp12(sm9Fp4Neg(x.a), sm9Fp4Neg(x.b), sm9Fp4Neg(x.c))
}
private func sm9Fp12Sub(x: Sm9Fp12, y: Sm9Fp12): Sm9Fp12 { sm9Fp12Add(x, sm9Fp12Neg(y)) }
private func sm9Fp12Mul(x: Sm9Fp12, y: Sm9Fp12): Sm9Fp12 {
    let c0 = sm9Fp4Add(sm9Fp4Mul(x.a, y.a), sm9Fp4MulV(sm9Fp4Add(sm9Fp4Mul(x.b, y.c), sm9Fp4Mul(x.c, y.b))))
    let c1 = sm9Fp4Add(
        sm9Fp4Add(sm9Fp4Mul(x.a, y.b), sm9Fp4Mul(x.b, y.a)),
        sm9Fp4MulV(sm9Fp4Mul(x.c, y.c))
    )
    let c2 = sm9Fp4Add(
        sm9Fp4Add(sm9Fp4Mul(x.a, y.c), sm9Fp4Mul(x.b, y.b)),
        sm9Fp4Mul(x.c, y.a)
    )
    Sm9Fp12(c0, c1, c2)
}
private func sm9Fp12Inverse(x: Sm9Fp12): Sm9Fp12 {
    let t0 = sm9Fp4Sub(sm9Fp4Mul(x.a, x.a), sm9Fp4MulV(sm9Fp4Mul(x.b, x.c)))
    let t1 = sm9Fp4Sub(sm9Fp4MulV(sm9Fp4Mul(x.c, x.c)), sm9Fp4Mul(x.a, x.b))
    let t2 = sm9Fp4Sub(sm9Fp4Mul(x.b, x.b), sm9Fp4Mul(x.a, x.c))
    let denominator = sm9Fp4Add(
        sm9Fp4Mul(x.a, t0),
        sm9Fp4MulV(sm9Fp4Add(sm9Fp4Mul(x.c, t1), sm9Fp4Mul(x.b, t2)))
    )
    let inverse = sm9Fp4Inverse(denominator)
    Sm9Fp12(sm9Fp4Mul(t0, inverse), sm9Fp4Mul(t1, inverse), sm9Fp4Mul(t2, inverse))
}
private func sm9Fp12Div(x: Sm9Fp12, y: Sm9Fp12): Sm9Fp12 { sm9Fp12Mul(x, sm9Fp12Inverse(y)) }
private func sm9Fp12Pow(value: Sm9Fp12, exponent: BigInt): Sm9Fp12 {
    var result = sm9Fp12One()
    var addend = value
    var remaining = exponent
    let one = BigInt(1)
    while (remaining > BigInt(0)) {
        if ((remaining & one) != BigInt(0)) {
            result = sm9Fp12Mul(result, addend)
        }
        addend = sm9Fp12Mul(addend, addend)
        remaining = remaining >> 1
    }
    result
}

private func sm9G1Internal(point: Sm9G1Point): Sm9G1 { Sm9G1(point.x.toBigInt(), point.y.toBigInt()) }
private func sm9G2Internal(point: Sm9G2Point): Sm9G2 {
    Sm9G2(
        Sm9Fp2(point.x0.toBigInt(), point.x1.toBigInt()),
        Sm9Fp2(point.y0.toBigInt(), point.y1.toBigInt())
    )
}
private func sm9G1OnCurve(point: Sm9G1): Bool {
    if (point.infinity || point.x < BigInt(0) || point.x >= SM9_P || point.y < BigInt(0) || point.y >= SM9_P) {
        return false
    }
    sm9ModP(point.y * point.y) == sm9ModP(point.x * point.x * point.x + BigInt(5))
}
private func sm9G2OnCurve(point: Sm9G2): Bool {
    if (point.infinity) { return false }
    let left = sm9Fp2Mul(point.y, point.y)
    let right = sm9Fp2Add(sm9Fp2Mul(sm9Fp2Mul(point.x, point.x), point.x), Sm9Fp2(BigInt(0), BigInt(5)))
    sm9Fp2Equal(left, right)
}
private func sm9G2Infinity(): Sm9G2 { Sm9G2(sm9Fp2Zero(), sm9Fp2Zero(), infinity: true) }
private func sm9G2Add(left: Sm9G2, right: Sm9G2): Sm9G2 {
    if (left.infinity) { return right }
    if (right.infinity) { return left }
    if (sm9Fp2Equal(left.x, right.x)) {
        if (!sm9Fp2Equal(left.y, right.y) || sm9Fp2IsZero(left.y)) { return sm9G2Infinity() }
    }
    let lambda = if (sm9Fp2Equal(left.x, right.x)) {
        sm9Fp2Mul(
            sm9Fp2Mul(Sm9Fp2(BigInt(3), BigInt(0)), sm9Fp2Mul(left.x, left.x)),
            sm9Fp2Inverse(sm9Fp2Mul(Sm9Fp2(BigInt(2), BigInt(0)), left.y))
        )
    } else {
        sm9Fp2Mul(sm9Fp2Sub(right.y, left.y), sm9Fp2Inverse(sm9Fp2Sub(right.x, left.x)))
    }
    let x = sm9Fp2Sub(sm9Fp2Sub(sm9Fp2Mul(lambda, lambda), left.x), right.x)
    let y = sm9Fp2Sub(sm9Fp2Mul(lambda, sm9Fp2Sub(left.x, x)), left.y)
    Sm9G2(x, y)
}
private func sm9G2Mul(point: Sm9G2, scalar: BigInt): Sm9G2 {
    var result = sm9G2Infinity()
    var addend = point
    var remaining = scalar
    let one = BigInt(1)
    while (remaining > BigInt(0)) {
        if ((remaining & one) != BigInt(0)) { result = sm9G2Add(result, addend) }
        addend = sm9G2Add(addend, addend)
        remaining = remaining >> 1
    }
    result
}

private func sm9TwistMap(point: Sm9G2): Sm9FullPoint {
    let inverseU = sm9Fp2Inverse(Sm9Fp2(BigInt(0), BigInt(1)))
    let xCoefficient = sm9Fp2Mul(point.x, inverseU)
    let yCoefficient = sm9Fp2Mul(point.y, inverseU)
    let x = Sm9Fp12(sm9Fp4Zero(), Sm9Fp4(sm9Fp2Zero(), xCoefficient), sm9Fp4Zero())
    let y = Sm9Fp12(Sm9Fp4(sm9Fp2Zero(), yCoefficient), sm9Fp4Zero(), sm9Fp4Zero())
    Sm9FullPoint(x, y)
}

private func sm9LineDouble(point: Sm9FullPoint, evaluation: Sm9FullPoint): Sm9LineStep {
    let lambda = sm9Fp12Div(
        sm9Fp12Mul(sm9Fp12Embed(BigInt(3)), sm9Fp12Mul(point.x, point.x)),
        sm9Fp12Mul(sm9Fp12Embed(BigInt(2)), point.y)
    )
    let x = sm9Fp12Sub(sm9Fp12Mul(lambda, lambda), sm9Fp12Add(point.x, point.x))
    let y = sm9Fp12Sub(sm9Fp12Mul(lambda, sm9Fp12Sub(point.x, x)), point.y)
    let line = sm9Fp12Sub(
        sm9Fp12Sub(evaluation.y, point.y),
        sm9Fp12Mul(lambda, sm9Fp12Sub(evaluation.x, point.x))
    )
    Sm9LineStep(Sm9FullPoint(x, y), line)
}

private func sm9LineAdd(point: Sm9FullPoint, addend: Sm9FullPoint, evaluation: Sm9FullPoint): Sm9LineStep {
    let lambda = sm9Fp12Div(sm9Fp12Sub(addend.y, point.y), sm9Fp12Sub(addend.x, point.x))
    let x = sm9Fp12Sub(sm9Fp12Sub(sm9Fp12Mul(lambda, lambda), point.x), addend.x)
    let y = sm9Fp12Sub(sm9Fp12Mul(lambda, sm9Fp12Sub(point.x, x)), point.y)
    let line = sm9Fp12Sub(
        sm9Fp12Sub(evaluation.y, point.y),
        sm9Fp12Mul(lambda, sm9Fp12Sub(evaluation.x, point.x))
    )
    Sm9LineStep(Sm9FullPoint(x, y), line)
}

private func sm9FrobeniusPoint(point: Sm9FullPoint): Sm9FullPoint {
    Sm9FullPoint(sm9Fp12Pow(point.x, SM9_P), sm9Fp12Pow(point.y, SM9_P))
}
private func sm9NegateFullPoint(point: Sm9FullPoint): Sm9FullPoint {
    Sm9FullPoint(point.x, sm9Fp12Neg(point.y))
}

private func sm9Pair(pointG1: Sm9G1, pointG2: Sm9G2): Sm9Fp12 {
    let evaluation = Sm9FullPoint(sm9Fp12Embed(pointG1.x), sm9Fp12Embed(pointG1.y))
    let base = sm9TwistMap(pointG2)
    var accumulator = sm9Fp12One()
    var running = base
    var bit = sm9BitLength(SM9_ATE_LOOP) - 2
    let one = BigInt(1)
    while (bit >= 0) {
        let doubled = sm9LineDouble(running, evaluation)
        running = doubled.point
        accumulator = sm9Fp12Mul(sm9Fp12Mul(accumulator, accumulator), doubled.line)
        if (((SM9_ATE_LOOP >> bit) & one) != BigInt(0)) {
            let added = sm9LineAdd(running, base, evaluation)
            running = added.point
            accumulator = sm9Fp12Mul(accumulator, added.line)
        }
        bit -= 1
    }
    let q1 = sm9FrobeniusPoint(base)
    let q2 = sm9NegateFullPoint(sm9FrobeniusPoint(q1))
    let firstTail = sm9LineAdd(running, q1, evaluation)
    accumulator = sm9Fp12Mul(accumulator, firstTail.line)
    let secondTail = sm9LineAdd(firstTail.point, q2, evaluation)
    accumulator = sm9Fp12Mul(accumulator, secondTail.line)
    sm9Fp12Pow(accumulator, SM9_FINAL_EXPONENT)
}

private func sm9Fp12ToBytes(value: Sm9Fp12): Array<Byte> {
    let output = Array<Byte>(SM9_TARGET_BYTES, repeat: UInt8(0))
    let coefficients: Array<BigInt> = [
        value.c.b.b, value.c.b.a, value.c.a.b, value.c.a.a,
        value.b.b.b, value.b.b.a, value.b.a.b, value.b.a.a,
        value.a.b.b, value.a.b.a, value.a.a.b, value.a.a.a
    ]
    var i: Int64 = 0
    while (i < coefficients.size) {
        sm9Copy(BigNum(coefficients[i]).toBytesBE(paddedLen: SM9_FIELD_BYTES), output, i * SM9_FIELD_BYTES)
        i += 1
    }
    output
}

private func sm9ModP(value: BigInt): BigInt {
    var reduced = value % SM9_P
    if (reduced.sign < 0) { reduced += SM9_P }
    reduced
}

private func sm9InverseP(value: BigInt): BigInt {
    let normalized = sm9ModP(value)
    if (normalized == BigInt(0)) {
        throw CryptoException(InvalidArgument, "SM9 field inverse does not exist")
    }
    try {
        return sm9ModP(normalized.modInverse(SM9_P))
    } catch (_: Exception) {
        throw CryptoException(InvalidArgument, "SM9 field inverse failed")
    }
}

private func sm9BitLength(value: BigInt): Int64 {
    let bytes = BigNum(value).toBytesBE()
    var top = bytes[0]
    var topBits: Int64 = 0
    while (top != UInt8(0)) { top = top >> UInt8(1); topBits += 1 }
    (bytes.size - 1) * 8 + topBits
}

private func sm9Big(hex: String): BigInt { BigNum.fromHex(hex).toBigInt() }

private func sm9Copy(input: Array<Byte>, output: Array<Byte>, offset: Int64): Unit {
    var i: Int64 = 0
    while (i < input.size) { output[offset + i] = input[i]; i += 1 }
}
