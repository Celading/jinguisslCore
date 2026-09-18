package jinguissl_tlcp_peer

import std.console.Console
import std.convert.*
import std.fs.File
import jinguissl_core.crypto.digest.bytesToHexLower
import jinguissl_core.crypto.tls.*
import jinguissl_core.crypto.x509.*

func readText(path: String): String { String.fromUtf8(File.readFrom(path)) }
func unhex(text: String): Array<Byte> {
    let raw = text.toArray()
    if (raw.size % 2 != 0) { throw Exception("odd hex input") }
    let bytes = Array<Byte>(raw.size / 2, repeat: 0)
    for (i in 0..raw.size) {
        let b = raw[i]
        let n = if (b >= 48 && b <= 57) { b - 48 } else if (b >= 97 && b <= 102) { b - 87 }
            else { throw Exception("invalid hex input") }
        bytes[i / 2] = (bytes[i / 2] << 4) | n
    }
    bytes
}

// Test-only line adapter. No secrets are exported by the session API.
main(args: Array<String>): Int64 {
    if (args.size != 4) { println("usage: client|server decimal-suite fixture-folder validation-time"); return 2 }
    let role = if (args[0] == "client") { TlcpRole.Client } else { TlcpRole.Server }
    let prefix = args[2] + "/" + args[0]
    let signKey = x509ParseSm2PrivateKeyPkcs8Pem(readText(prefix + "-sign.key"))
    let encKey = x509ParseSm2PrivateKeyPkcs8Pem(readText(prefix + "-enc.key"))
    let identity = TlcpIdentity(signKey.scalar.toBytesBE(paddedLen: 32), encKey.scalar.toBytesBE(paddedLen: 32),
        x509ParsePem(readText(prefix + "-sign.pem")).der, x509ParsePem(readText(prefix + "-enc.pem")).der)
    let session = TlcpSession(role, readText(args[2] + "/root.pem"), args[3],
        expectedPeerDnsName: if (role == TlcpRole.Client) { "localhost" } else { "" }, identity: Some(identity),
        policy: TlcpProviderPolicy(cipherSuites: [tlcpCipherSuiteFromWire(Int64.parse(args[1]))],
            requireClientCertificate: true))
    identity.destroy()
    try {
        session.start(0)
        while (true) {
            for (wire in session.takeOutput()) { println("OUT " + bytesToHexLower(wire)) }
            println("READY " + session.handshakeComplete.toString())
            Console.stdOut.flush()
            let line = match (Console.stdIn.readln()) { case Some(value) => value; case None => break }
            let parts = line.split(' ')
            if (parts[0] == "QUIT") { break }
            if (parts[0] == "RX") {
                for (plain in session.receive(unhex(parts[2]), Int64.parse(parts[1]))) {
                    println("DATA " + bytesToHexLower(plain))
                }
            } else if (parts[0] == "TICK") { session.onTimeout(Int64.parse(parts[1])) }
            else if (parts[0] == "APP") { println("OUT " + bytesToHexLower(session.sealApplicationData(unhex(parts[1])))) }
            else if (parts[0] == "CLOSE") { session.closeNotify() }
        }
    } catch (e: TlcpProviderException) { println("FAIL " + e.reason + " " + e.message); return 1 }
      finally { session.close() }
    0
}
