#!/usr/bin/env python3
"""Independent TLCP reference replay. openHiTLS is a test process, never a backend.

Build examples/tlcp-peer and a fixed official openHiTLS revision first. The runner
uses fresh, distinct SM2 client/server dual identities under an ephemeral root,
mutual certificate authentication, both roles and all four configured suites.
"""
import argparse
from datetime import datetime, timezone
import os
from pathlib import Path
import platform
import queue
import shutil
import select
import socket
import subprocess
import tempfile
import threading
import time

SUITES = {0xE011: "TLS_ECDHE_SM4_CBC_SM3", 0xE013: "TLS_ECC_SM4_CBC_SM3",
          0xE051: "TLS_ECDHE_SM4_GCM_SM3", 0xE053: "TLS_ECC_SM4_GCM_SM3"}


def fixture(openssl, folder):
    """Independent PKI fixtures: CA basicConstraints, distinct leaves, explicit SM2 ID."""
    def run(*args):
        subprocess.run([openssl, *args], cwd=folder, check=True, stdout=subprocess.PIPE,
                       stderr=subprocess.PIPE, timeout=20)
    run("genpkey", "-algorithm", "SM2", "-out", "root.key")
    run("req", "-new", "-x509", "-key", "root.key", "-sm3", "-sigopt", "distid:1234567812345678",
        "-subj", "/CN=TLCP Test Root", "-days", "3650", "-addext", "basicConstraints=critical,CA:TRUE",
        "-addext", "keyUsage=critical,keyCertSign,cRLSign", "-out", "root.pem")
    serial = 2
    for role in ("client", "server"):
        for purpose in ("sign", "enc"):
            stem = f"{role}-{purpose}"
            usage = "digitalSignature" if purpose == "sign" else "keyEncipherment,dataEncipherment,keyAgreement"
            (folder / f"{stem}.ext").write_text("basicConstraints=critical,CA:FALSE\n" +
                f"keyUsage=critical,{usage}\nsubjectAltName=DNS:localhost\n")
            run("genpkey", "-algorithm", "SM2", "-out", f"{stem}.key")
            run("req", "-new", "-key", f"{stem}.key", "-subj", "/CN=localhost", "-sm3",
                "-sigopt", "distid:1234567812345678", "-out", f"{stem}.csr")
            run("x509", "-req", "-in", f"{stem}.csr", "-CA", "root.pem", "-CAkey", "root.key",
                "-set_serial", str(serial), "-days", "3650", "-sm3", "-sigopt", "distid:1234567812345678",
                "-vfyopt", "distid:1234567812345678", "-extfile", f"{stem}.ext", "-out", f"{stem}.pem")
            serial += 1


def peer_env():
    env = os.environ.copy()
    sdk = Path(env["CANGJIE_HOME"])
    host = "darwin" if platform.system() == "Darwin" else "linux"
    arch = "aarch64" if platform.machine() in ("arm64", "aarch64") else "x86_64"
    runtime = sdk / "runtime/lib" / f"{host}_{arch}_cjnative"
    if not runtime.is_dir():
        raise RuntimeError(f"SDK runtime missing: {runtime}")
    variable = "DYLD_LIBRARY_PATH" if host == "darwin" else "LD_LIBRARY_PATH"
    env[variable] = os.pathsep.join([str(runtime), str(sdk / "tools/lib"), env.get(variable, "")])
    return env


def run_case(binary, reference, folder, role, suite):
    processes = []
    sockets = []
    own_lines = []
    ref_role = "server" if role == "client" else "client"
    with tempfile.TemporaryFile() as reference_log:
        try:
            listener = socket.socket()
            sockets.append(listener)
            listener.bind(("127.0.0.1", 0))
            port = listener.getsockname()[1]
            if role == "server":
                listener.listen(); listener.settimeout(10)
            else:
                listener.close()
            args = [str(reference), ref_role, str(port), hex(suite), str(folder)]
            ref = subprocess.Popen(args, stdin=subprocess.PIPE, stdout=reference_log, stderr=subprocess.STDOUT)
            processes.append(ref)
            if role == "server":
                sock, _ = listener.accept()
            else:
                deadline = time.monotonic() + 10
                while True:
                    try:
                        sock = socket.create_connection(("127.0.0.1", port), timeout=1)
                        break
                    except OSError:
                        if time.monotonic() >= deadline or ref.poll() is not None:
                            raise AssertionError("reference did not listen")
                        time.sleep(0.05)
            sockets.append(sock); sock.settimeout(5)
            peer = subprocess.Popen([str(binary), role, str(suite), str(folder),
                                    datetime.now(timezone.utc).strftime("%y%m%d%H%M%SZ")], env=peer_env(),
                                    stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
            processes.append(peer)
            lines = queue.Queue()
            def reader():
                for line in peer.stdout:
                    lines.put(line.decode(errors="replace").rstrip())
                lines.put(None)
            threading.Thread(target=reader, daemon=True).start()
            data = []
            ever_ready = False
            def drain():
                nonlocal ever_ready
                while True:
                    line = lines.get(timeout=15)
                    if line is None:
                        raise AssertionError("Cangjie peer exited")
                    own_lines.append(line)
                    if line.startswith("FAIL "):
                        raise AssertionError(line)
                    if line.startswith("OUT "):
                        sock.sendall(bytes.fromhex(line[4:]))
                    if line.startswith("DATA "):
                        data.append(bytes.fromhex(line[5:]))
                    if line.startswith("READY "):
                        ever_ready |= line == "READY true"
                        return
            def command(value):
                peer.stdin.write((value + "\n").encode()); peer.stdin.flush(); drain()
            drain()
            start = time.monotonic()
            sent = False
            while time.monotonic() - start < 20:
                if ever_ready and not sent and (role == "client" or data):
                    command("APP " + b"jinguissl-to-hitls\n".hex()); sent = True
                if data and sent:
                    break
                if select.select([sock], [], [], 0.1)[0]:
                    packet = sock.recv(65536)
                    if not packet:
                        raise AssertionError("reference closed before application proof")
                    own_lines.append("IN " + packet[:96].hex())
                    command(f"RX {int((time.monotonic() - start) * 1000)} {packet.hex()}")
            assert ever_ready and sent and data, "missing handshake or bidirectional application evidence"
            assert b"hitls-to-jinguissl\n" in b"".join(data), "unexpected reference application bytes"
            ref.wait(timeout=10)
            reference_log.seek(0)
            text = reference_log.read().decode(errors="replace")
            assert ref.returncode == 0, text
            assert "TLS handshake completed successfully" in text, text
            assert f"suite={hex(suite)} verified=true" in text, text
            assert "jinguissl-to-hitls" in text, text
            print(f"PASS role={role} suite={SUITES[suite]} mutual-cert=true bidirectional-data=true", flush=True)
        except Exception as error:
            reference_log.seek(0)
            text = reference_log.read().decode(errors="replace")
            raise AssertionError(f"{role} {SUITES[suite]}: {error}\nPEER:\n" +
                                 "\n".join(own_lines[-16:]) + "\nREFERENCE:\n" + text) from error
        finally:
            for process in processes:
                if process.poll() is None:
                    process.terminate()
                try:
                    process.wait(timeout=3)
                except subprocess.TimeoutExpired:
                    process.kill(); process.wait()
            for sock in sockets:
                sock.close()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", required=True, type=Path)
    parser.add_argument("--reference", required=True, type=Path)
    parser.add_argument("--openssl", default=shutil.which("openssl"), help="OpenSSL 3+ fixture generator")
    parser.add_argument("--suite", type=lambda s: int(s, 0), choices=SUITES)
    parser.add_argument("--role", choices=["client", "server"])
    args = parser.parse_args()
    binary = args.binary.resolve(); reference = args.reference.resolve()
    with tempfile.TemporaryDirectory(prefix="jinguissl-tlcp-") as temporary:
        folder = Path(temporary)
        if not args.openssl:
            parser.error("OpenSSL 3+ is required for independent certificate fixtures")
        fixture(args.openssl, folder)
        for suite in [args.suite] if args.suite else SUITES:
            for role in [args.role] if args.role else ["client", "server"]:
                run_case(binary, reference, folder, role, suite)


if __name__ == "__main__":
    main()
