package jinguissl_core.tests

import jinguissl_core.crypto.error.CryptoException
import jinguissl_core.crypto.tls.*

@Test
public class CoreDtlcpTestSuite {
    @TestCase
    public func testDtlcpCbcAndGcmRecordsAcceptOutOfOrderAndRejectReplay(): Unit {
        for (suite in [ECDHE_SM4_CBC_SM3, ECDHE_SM4_GCM_SM3]) {
            let secrets = dtlcpTestSecrets(suite)
            let sender = dtlcpCreateClientRecordLayer(secrets, epoch: 1)
            let receiver = dtlcpCreateServerRecordLayer(secrets, epoch: 1)
            let first = sender.seal(ApplicationData, "datagram-zero".toArray())
            let second = sender.seal(Handshake, "datagram-one".toArray())

            let openedSecond = receiver.open(second)
            @Assert(openedSecond.sequence, 1)
            @Assert(openedSecond.fragment, "datagram-one".toArray())
            let openedFirst = receiver.open(first)
            @Assert(openedFirst.sequence, 0)
            @Assert(openedFirst.fragment, "datagram-zero".toArray())
            dtlcpAssertRejected({ => _ = receiver.open(first) })
        }
    }

    @TestCase
    public func testDtlcpTamperDoesNotPoisonReplayWindowAndEpochTransitions(): Unit {
        let secrets = dtlcpTestSecrets(ECDHE_SM4_GCM_SM3)
        let sender = dtlcpCreateClientRecordLayer(secrets, epoch: 3)
        let receiver = dtlcpCreateServerRecordLayer(secrets, epoch: 3)
        let encoded = sender.seal(ApplicationData, "epoch-three".toArray())
        let tampered = encoded.clone()
        tampered[tampered.size - 1] ^= UInt8(1)
        dtlcpAssertRejected({ => _ = receiver.open(tampered) })
        @Assert(receiver.highestReadSequence, -1)
        @Assert(receiver.open(encoded).fragment, "epoch-three".toArray())

        sender.setEpoch(4)
        receiver.setEpoch(4)
        let nextEpoch = sender.seal(ApplicationData, "epoch-four".toArray())
        let (header, _) = dtlcpDecodeRecord(nextEpoch)
        @Assert(header.epoch, 4)
        @Assert(header.sequence, 0)
        @Assert(receiver.open(nextEpoch).fragment, "epoch-four".toArray())
        dtlcpAssertRejected({ => receiver.setEpoch(2) })
    }

    @TestCase
    public func testDtlcpReplayWindowSlidesAcrossSixtyFourPackets(): Unit {
        let window = DtlcpReplayWindow()
        window.markAccepted(4)
        window.markAccepted(2)
        @Assert(window.canAccept(3), true)
        @Assert(window.canAccept(2), false)
        window.markAccepted(80)
        @Assert(window.highestSequence, 80)
        @Assert(window.canAccept(4), false)
        @Assert(window.canAccept(79), true)
    }

    @TestCase
    public func testDtlcpHandshakeFragmentationAndOutOfOrderReassembly(): Unit {
        let body = dtlcpTestBytes(173, UInt8(0x30))
        let handshake = dtlcpTestHandshake(UInt8(0x0b), body)
        let fragments = dtlcpFragmentHandshake(handshake, 7, 41)
        @Assert(fragments.size, 5)
        let reassembler = DtlcpHandshakeReassembler(UInt8(0x0b), body.size, 7)
        @Assert(reassembler.accept(fragments[4]), false)
        @Assert(reassembler.accept(fragments[2]), false)
        @Assert(reassembler.accept(fragments[0]), false)
        @Assert(reassembler.accept(fragments[1]), false)
        @Assert(reassembler.accept(fragments[3]), true)
        @Assert(reassembler.encodedHandshake(), handshake)
        @Assert(reassembler.accept(fragments[3]), true)
    }

    @TestCase
    public func testDtlcpReassemblyRejectsInconsistentOverlapAndBounds(): Unit {
        let body = dtlcpTestBytes(32, UInt8(0x70))
        let reassembler = DtlcpHandshakeReassembler(UInt8(0x01), body.size, 2)
        let first = DtlcpHandshakeFragment(UInt8(0x01), body.size, 2, 0, body[0..16])
        @Assert(reassembler.acceptFragment(first), false)
        let conflicting = body[8..24]
        conflicting[0] ^= UInt8(1)
        dtlcpAssertRejected({ =>
            _ = reassembler.acceptFragment(DtlcpHandshakeFragment(
                UInt8(0x01), body.size, 2, 8, conflicting
            ))
        })
        dtlcpAssertRejected({ =>
            _ = DtlcpHandshakeFragment(UInt8(0x01), 10, 0, 9, [UInt8(1), UInt8(2)])
        })
    }

    @TestCase
    public func testDtlcpCachedFlightBackoffAndIsolation(): Unit {
        let retransmitter = DtlcpFlightRetransmitter(
            initialTimeoutMillis: 100,
            maxTimeoutMillis: 350,
            maxAttempts: 3
        )
        let original = [[UInt8(1), UInt8(2)], [UInt8(3)]]
        retransmitter.cacheFlight(original)
        original[0][0] = UInt8(9)
        let first = retransmitter.nextFlight()
        @Assert(first[0][0], UInt8(1))
        @Assert(retransmitter.timeoutMillis, 200)
        first[0][0] = UInt8(8)
        @Assert(retransmitter.nextFlight()[0][0], UInt8(1))
        @Assert(retransmitter.timeoutMillis, 350)
        _ = retransmitter.nextFlight()
        @Assert(retransmitter.hasPendingFlight, false)
        dtlcpAssertRejected({ => _ = retransmitter.nextFlight() })
        retransmitter.acknowledgeFlight()
        @Assert(retransmitter.attempts, 0)
        @Assert(retransmitter.hasPendingFlight, false)
    }
}

private func dtlcpTestSecrets(suite: TlcpCipherSuite): TlcpHandshakeSecrets {
    tlcpDeriveSecretsFromPreMaster(
        dtlcpTestBytes(48, UInt8(0x11)),
        dtlcpTestBytes(32, UInt8(0x41)),
        dtlcpTestBytes(32, UInt8(0x81)),
        suite
    )
}

private func dtlcpTestHandshake(messageType: Byte, body: Array<Byte>): Array<Byte> {
    let output = Array<Byte>(body.size + 4, repeat: UInt8(0))
    output[0] = messageType
    output[1] = UInt8((body.size >> 16) & 0xff)
    output[2] = UInt8((body.size >> 8) & 0xff)
    output[3] = UInt8(body.size & 0xff)
    var i: Int64 = 0
    while (i < body.size) { output[4 + i] = body[i]; i += 1 }
    output
}

private func dtlcpTestBytes(size: Int64, start: Byte): Array<Byte> {
    let output = Array<Byte>(size, repeat: UInt8(0))
    var i: Int64 = 0
    while (i < size) {
        output[i] = UInt8((Int64(start) + i) & 0xff)
        i += 1
    }
    output
}

private func dtlcpAssertRejected(action: () -> Unit): Unit {
    var rejected = false
    try {
        action()
    } catch (_: CryptoException) {
        rejected = true
    }
    @Assert(rejected, true)
}
