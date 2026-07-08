import argparse
import base64
import json
import subprocess
import sys
import time
from pathlib import Path


TEST_CLIENT_SEED_HEX = "00112233445566778899aabbccddeeff102132435465768798a9bacbdcedfe0f"
TEST_SERVER_SEED_HEX = "f0e1d2c3b4a5968778695a4b3c2d1e0fefdecdbcab9a89786756453423120100"
DEFAULT_SIZES = [1, 16, 64, 256, 512, 840]
DEFAULT_CL_PATH = r"C:\Program Files\Microsoft Visual Studio\18\Community\VC\Tools\MSVC\14.50.35717\bin\Hostx86\x86\cl.exe"
DEFAULT_VCVARS_PATH = r"C:\Program Files\Microsoft Visual Studio\18\Community\VC\Auxiliary\Build\vcvars32.bat"


MODULE_ROOT = Path(__file__).resolve().parents[1]
TEST_ROOT = Path(__file__).resolve().parent
BIN_ROOT = TEST_ROOT / "bin"
PYTHON_PEER_SCRIPT = Path(__file__).resolve()
GO_PEER_EXE = BIN_ROOT / "go_peer.exe"
C_PEER_EXE = BIN_ROOT / "c_peer.exe"
C_PEER_SOURCE = TEST_ROOT / "c_peer.c"

if str(MODULE_ROOT) not in sys.path:
    sys.path.insert(0, str(MODULE_ROOT))

import naion  # noqa: E402


def payload_for_size(size: int) -> bytes:
    return bytes(((size * 17) + i * 29) & 0xFF for i in range(size))


def b64e(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


def b64d(text: str) -> bytes:
    return base64.b64decode(text.encode("ascii"))


def json_print(obj: dict) -> None:
    print(json.dumps(obj, separators=(",", ":")))


def run_process(command: list[str], cwd: Path | None = None) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        command,
        cwd=str(cwd) if cwd else None,
        check=True,
        capture_output=True,
        text=True,
    )


def build_go_peer(go_exe: str) -> None:
    BIN_ROOT.mkdir(parents=True, exist_ok=True)
    run_process([go_exe, "build", "-o", str(GO_PEER_EXE), "./test/go_peer"], cwd=MODULE_ROOT)


def build_c_peer(cl_path: str, vcvars_path: str) -> None:
    BIN_ROOT.mkdir(parents=True, exist_ok=True)
    batch_path = BIN_ROOT / "build_c_peer.bat"
    batch_path.write_text(
        "\n".join(
            [
                "@echo off",
                f'call "{vcvars_path}" >nul',
                "if errorlevel 1 exit /b 1",
                f'"{cl_path}" /nologo /O2 /TC /D_CRT_SECURE_NO_WARNINGS /I"{MODULE_ROOT}" "{C_PEER_SOURCE}" /Fe:"{C_PEER_EXE}"',
            ]
        ),
        encoding="utf-8",
    )
    completed = subprocess.run(
        [str(batch_path)],
        cwd=str(BIN_ROOT),
        capture_output=True,
        text=True,
    )
    if completed.returncode != 0:
        raise RuntimeError(
            "C peer build failed\n"
            f"stdout:\n{completed.stdout}\n"
            f"stderr:\n{completed.stderr}"
        )


def peer_python(args: argparse.Namespace) -> int:
    client_seed = bytes.fromhex(args.client_seed)
    server_seed = bytes.fromhex(args.server_seed)
    repeat = max(1, int(args.repeat))
    server = naion.CSMServer(server_seed)
    client = naion.CSMClient(client_seed, server.ed_public_key)

    if args.op == "client-encrypt":
        payload = b64d(args.payload_b64)
        begin = time.perf_counter_ns()
        packet = b""
        for _ in range(repeat):
            packet = client.encrypt(payload)
        elapsed_ns = time.perf_counter_ns() - begin
        json_print({"ok": True, "elapsed_ns": elapsed_ns, "repeat": repeat, "packet_b64": b64e(packet)})
        return 0

    if args.op == "server-decrypt":
        packet = b64d(args.packet_b64)
        begin = time.perf_counter_ns()
        plaintext = b""
        for _ in range(repeat):
            plaintext = server.decrypt(packet)
        elapsed_ns = time.perf_counter_ns() - begin
        json_print({"ok": True, "elapsed_ns": elapsed_ns, "repeat": repeat, "plaintext_b64": b64e(plaintext)})
        return 0

    if args.op == "server-encrypt":
        bootstrap_packet = b64d(args.bootstrap_packet_b64)
        payload = b64d(args.payload_b64)
        server.decrypt(bootstrap_packet)
        begin = time.perf_counter_ns()
        packet = b""
        for _ in range(repeat):
            packet = server.encrypt(payload)
        elapsed_ns = time.perf_counter_ns() - begin
        json_print({"ok": True, "elapsed_ns": elapsed_ns, "repeat": repeat, "packet_b64": b64e(packet)})
        return 0

    if args.op == "client-decrypt":
        packet = b64d(args.packet_b64)
        begin = time.perf_counter_ns()
        plaintext = b""
        for _ in range(repeat):
            plaintext = client.decrypt(packet)
        elapsed_ns = time.perf_counter_ns() - begin
        json_print({"ok": True, "elapsed_ns": elapsed_ns, "repeat": repeat, "plaintext_b64": b64e(plaintext)})
        return 0

    raise ValueError(f"unknown op: {args.op}")


class Peer:
    def __init__(self, name: str, command: list[str], client_seed: str, server_seed: str) -> None:
        self.name = name
        self.command = command
        self.client_seed = client_seed
        self.server_seed = server_seed

    def invoke(
        self,
        op: str,
        payload: bytes | None = None,
        packet: bytes | None = None,
        bootstrap_packet: bytes | None = None,
        repeat: int = 1,
        extra_args: dict[str, str | int] | None = None,
    ) -> dict:
        command = list(self.command)
        command.extend(
            [
                op,
                "--client-seed",
                self.client_seed,
                "--server-seed",
                self.server_seed,
                "--repeat",
                str(repeat),
            ]
        )
        if extra_args:
            for key, value in extra_args.items():
                command.extend([f"--{key}", str(value)])
        if payload is not None:
            command.extend(["--payload-b64", b64e(payload)])
        if packet is not None:
            command.extend(["--packet-b64", b64e(packet)])
        if bootstrap_packet is not None:
            command.extend(["--bootstrap-packet-b64", b64e(bootstrap_packet)])
        try:
            completed = run_process(command, cwd=MODULE_ROOT)
        except subprocess.CalledProcessError as exc:
            return {
                "ok": False,
                "error": (
                    f"command failed: {' '.join(command)}\n"
                    f"stdout:\n{exc.stdout}\n"
                    f"stderr:\n{exc.stderr}"
                ),
            }
        try:
            return json.loads(completed.stdout.strip())
        except json.JSONDecodeError as exc:
            return {
                "ok": False,
                "error": (
                    f"{self.name} returned invalid JSON.\n"
                    f"stdout:\n{completed.stdout}\n"
                    f"stderr:\n{completed.stderr}"
                ),
            }


def avg_ns(result: dict) -> float:
    repeat = max(1, int(result.get("repeat", 1)))
    return float(result["elapsed_ns"]) / float(repeat)


def format_us_from_ns(elapsed_ns: float) -> str:
    return f"{elapsed_ns / 1000.0:.1f}us"


def print_result(mode: str, size: int, enc_lang: str, dec_lang: str, enc_ns: float, dec_ns: float) -> None:
    total_ns = enc_ns + dec_ns
    print(
        f"[{mode}] size={size:>3} {enc_lang:>6} -> {dec_lang:<6} "
        f"enc={format_us_from_ns(enc_ns):>10} dec={format_us_from_ns(dec_ns):>10} total={format_us_from_ns(total_ns):>10}"
    )


def print_failure(mode: str, size: int, enc_lang: str, dec_lang: str, stage: str, error: str) -> None:
    headline = f"[{mode}] size={size:>3} {enc_lang:>6} -> {dec_lang:<6} {stage}=FAIL"
    print(headline)
    print(error.strip())


def run_suite(args: argparse.Namespace) -> int:
    sizes = [int(item) for item in args.sizes.split(",") if item.strip()]
    repeat = max(1, int(args.repeat))
    if not sizes:
        raise ValueError("sizes must not be empty")

    build_go_peer(args.go)
    build_c_peer(args.cl_path, args.vcvars_path)

    peers = [
        Peer(
            "python",
            [sys.executable, str(PYTHON_PEER_SCRIPT), "peer-python"],
            args.client_seed,
            args.server_seed,
        ),
        Peer("go", [str(GO_PEER_EXE)], args.client_seed, args.server_seed),
        Peer("c", [str(C_PEER_EXE)], args.client_seed, args.server_seed),
    ]

    results: list[dict] = []
    passed = 0
    failed = 0

    print("== Client -> Server ==")
    for size in sizes:
        payload = payload_for_size(size)
        for enc_peer in peers:
            enc = enc_peer.invoke("client-encrypt", payload=payload, repeat=repeat)
            if not enc.get("ok", False):
                failed += len(peers)
                for dec_peer in peers:
                    print_failure("C2S", size, enc_peer.name, dec_peer.name, "encrypt", enc["error"])
                    results.append(
                        {
                            "mode": "client_to_server",
                            "size": size,
                            "encryptor": enc_peer.name,
                            "decryptor": dec_peer.name,
                            "status": "encrypt_failed",
                            "error": enc["error"],
                        }
                    )
                continue
            packet = b64d(enc["packet_b64"])
            for dec_peer in peers:
                dec = dec_peer.invoke("server-decrypt", packet=packet, repeat=repeat)
                if not dec.get("ok", False):
                    failed += 1
                    print_failure("C2S", size, enc_peer.name, dec_peer.name, "decrypt", dec["error"])
                    results.append(
                        {
                            "mode": "client_to_server",
                            "size": size,
                            "encryptor": enc_peer.name,
                            "decryptor": dec_peer.name,
                            "status": "decrypt_failed",
                            "encrypt_ns": enc["elapsed_ns"],
                            "error": dec["error"],
                        }
                    )
                    continue
                plaintext = b64d(dec["plaintext_b64"])
                if plaintext != payload:
                    failed += 1
                    error = f"plaintext mismatch: expected {len(payload)} bytes, got {len(plaintext)} bytes"
                    print_failure("C2S", size, enc_peer.name, dec_peer.name, "verify", error)
                    results.append(
                        {
                            "mode": "client_to_server",
                            "size": size,
                            "encryptor": enc_peer.name,
                            "decryptor": dec_peer.name,
                            "status": "verify_failed",
                            "encrypt_ns": enc["elapsed_ns"],
                            "decrypt_ns": dec["elapsed_ns"],
                            "error": error,
                        }
                    )
                    continue
                passed += 1
                enc_avg_ns = avg_ns(enc)
                dec_avg_ns = avg_ns(dec)
                print_result("C2S", size, enc_peer.name, dec_peer.name, enc_avg_ns, dec_avg_ns)
                results.append(
                    {
                        "mode": "client_to_server",
                        "size": size,
                        "encryptor": enc_peer.name,
                        "decryptor": dec_peer.name,
                        "status": "ok",
                        "encrypt_ns": enc["elapsed_ns"],
                        "decrypt_ns": dec["elapsed_ns"],
                        "repeat": repeat,
                    }
                )

    print("\n== Server -> Client ==")
    bootstrap_payload = b"bootstrap"
    for size in sizes:
        payload = payload_for_size(size)
        for enc_peer in peers:
            bootstrap = enc_peer.invoke("client-encrypt", payload=bootstrap_payload, repeat=1)
            if not bootstrap.get("ok", False):
                failed += len(peers)
                for dec_peer in peers:
                    print_failure("S2C", size, enc_peer.name, dec_peer.name, "bootstrap", bootstrap["error"])
                    results.append(
                        {
                            "mode": "server_to_client",
                            "size": size,
                            "encryptor": enc_peer.name,
                            "decryptor": dec_peer.name,
                            "status": "bootstrap_failed",
                            "error": bootstrap["error"],
                        }
                    )
                continue
            bootstrap_packet = b64d(bootstrap["packet_b64"])
            enc = enc_peer.invoke("server-encrypt", payload=payload, bootstrap_packet=bootstrap_packet, repeat=repeat)
            if not enc.get("ok", False):
                failed += len(peers)
                for dec_peer in peers:
                    print_failure("S2C", size, enc_peer.name, dec_peer.name, "encrypt", enc["error"])
                    results.append(
                        {
                            "mode": "server_to_client",
                            "size": size,
                            "encryptor": enc_peer.name,
                            "decryptor": dec_peer.name,
                            "status": "encrypt_failed",
                            "error": enc["error"],
                        }
                    )
                continue
            packet = b64d(enc["packet_b64"])
            for dec_peer in peers:
                dec = dec_peer.invoke("client-decrypt", packet=packet, repeat=repeat)
                if not dec.get("ok", False):
                    failed += 1
                    print_failure("S2C", size, enc_peer.name, dec_peer.name, "decrypt", dec["error"])
                    results.append(
                        {
                            "mode": "server_to_client",
                            "size": size,
                            "encryptor": enc_peer.name,
                            "decryptor": dec_peer.name,
                            "status": "decrypt_failed",
                            "encrypt_ns": enc["elapsed_ns"],
                            "error": dec["error"],
                        }
                    )
                    continue
                plaintext = b64d(dec["plaintext_b64"])
                if plaintext != payload:
                    failed += 1
                    error = f"plaintext mismatch: expected {len(payload)} bytes, got {len(plaintext)} bytes"
                    print_failure("S2C", size, enc_peer.name, dec_peer.name, "verify", error)
                    results.append(
                        {
                            "mode": "server_to_client",
                            "size": size,
                            "encryptor": enc_peer.name,
                            "decryptor": dec_peer.name,
                            "status": "verify_failed",
                            "encrypt_ns": enc["elapsed_ns"],
                            "decrypt_ns": dec["elapsed_ns"],
                            "error": error,
                        }
                    )
                    continue
                passed += 1
                enc_avg_ns = avg_ns(enc)
                dec_avg_ns = avg_ns(dec)
                print_result("S2C", size, enc_peer.name, dec_peer.name, enc_avg_ns, dec_avg_ns)
                results.append(
                    {
                        "mode": "server_to_client",
                        "size": size,
                        "encryptor": enc_peer.name,
                        "decryptor": dec_peer.name,
                        "status": "ok",
                        "encrypt_ns": enc["elapsed_ns"],
                        "decrypt_ns": dec["elapsed_ns"],
                        "repeat": repeat,
                    }
                )

    if args.json_out:
        json_path = Path(args.json_out)
        json_path.write_text(json.dumps(results, indent=2), encoding="utf-8")
        print(f"\njson results written to: {json_path}")

    print(f"\ninterop run complete: passed={passed}, failed={failed}, total={len(results)}")
    return 0 if failed == 0 else 1


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Naion C/Go/Python interop and timing test tool")
    subparsers = parser.add_subparsers(dest="command", required=True)

    peer_parser = subparsers.add_parser("peer-python", help="python peer endpoint for the interop runner")
    peer_parser.add_argument("op", choices=["client-encrypt", "server-decrypt", "server-encrypt", "client-decrypt"])
    peer_parser.add_argument("--client-seed", required=True)
    peer_parser.add_argument("--server-seed", required=True)
    peer_parser.add_argument("--payload-b64")
    peer_parser.add_argument("--packet-b64")
    peer_parser.add_argument("--bootstrap-packet-b64")
    peer_parser.add_argument("--repeat", default="1")
    peer_parser.set_defaults(func=peer_python)

    run_parser = subparsers.add_parser("run", help="run the full cross-language interop suite")
    run_parser.add_argument("--client-seed", default=TEST_CLIENT_SEED_HEX)
    run_parser.add_argument("--server-seed", default=TEST_SERVER_SEED_HEX)
    run_parser.add_argument("--sizes", default=",".join(str(size) for size in DEFAULT_SIZES))
    run_parser.add_argument("--go", default="go")
    run_parser.add_argument("--cl-path", default=DEFAULT_CL_PATH)
    run_parser.add_argument("--vcvars-path", default=DEFAULT_VCVARS_PATH)
    run_parser.add_argument("--repeat", default="100")
    run_parser.add_argument("--json-out")
    run_parser.set_defaults(func=run_suite)

    return parser


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()
    return int(args.func(args))


if __name__ == "__main__":
    raise SystemExit(main())
    repeat = max(1, int(args.repeat))
