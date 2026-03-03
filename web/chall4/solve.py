#!/usr/bin/env python3
import argparse
import json
import os
import random
import re
import socket
import string
import subprocess
import sys
import time
from pathlib import Path

import requests


BASE = "http://158.160.221.45:4818"
BOT_HOST = "158.160.221.45"
BOT_PORT = 1557


def randstr(prefix="u", n=10):
    alphabet = string.ascii_lowercase + string.digits
    return prefix + "".join(random.choice(alphabet) for _ in range(n))


class Client:
    def __init__(self, base=BASE):
        self.base = base.rstrip("/")
        self.s = requests.Session()

    def url(self, path):
        return self.base + path

    def req(self, method, path, **kwargs):
        r = self.s.request(method, self.url(path), timeout=30, **kwargs)
        return r

    def register(self, username, password):
        r = self.req("POST", "/api/auth/register", json={"username": username, "password": password})
        r.raise_for_status()
        return r.json()

    def login(self, username, password):
        r = self.req("POST", "/api/auth/login", json={"username": username, "password": password})
        r.raise_for_status()
        return r.json()

    def me(self):
        r = self.req("GET", "/api/auth/me")
        return r

    def create_note(self, title, content, is_public=False):
        r = self.req("POST", "/api/notes", json={"title": title, "content": content, "isPublic": is_public})
        r.raise_for_status()
        return r.json()

    def get_note(self, uuid):
        r = self.req("GET", f"/api/notes/{uuid}")
        r.raise_for_status()
        return r.json()

    def list_notes(self):
        r = self.req("GET", "/api/notes")
        r.raise_for_status()
        return r.json()

    def upload_video(self, path, mime="video/mp4"):
        with open(path, "rb") as f:
            files = {"video": (os.path.basename(path), f, mime)}
            r = self.req("POST", "/api/videos", files=files)
        if not r.ok:
            raise requests.HTTPError(f"{r.status_code} {r.text}", response=r)
        return r.json()


def raw_tls_get(ip, host, path):
    req = f"GET {path} HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n"
    cmd = [
        "openssl",
        "s_client",
        "-quiet",
        "-servername",
        host,
        "-connect",
        f"{ip}:443",
    ]
    p = subprocess.run(
        cmd,
        input=req.encode(),
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        timeout=30,
        check=False,
    )
    data = p.stdout.decode("utf-8", "replace")
    return p.returncode, p.stderr.decode("utf-8", "replace"), data


def solve_pow(resource, bits):
    fastpow = Path(__file__).with_name("fastpow")
    if fastpow.exists():
        p = subprocess.run(
            [str(fastpow), str(bits), resource],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=30,
            check=False,
            text=True,
        )
        if p.returncode == 0:
            stamp = p.stdout.strip()
            if stamp:
                return stamp

    target = bits
    prefix = f"1:{bits}:250228:{resource}::"
    counter = 0
    while True:
        stamp = prefix + f"rnd:{counter:x}"
        h = __import__("hashlib").sha1(stamp.encode()).digest()
        zeros = 0
        for b in h:
            if b == 0:
                zeros += 8
                continue
            while (b & 0x80) == 0:
                zeros += 1
                b <<= 1
            break
        if zeros >= target:
            return stamp
        counter += 1


def bot_visit(uuid, host=BOT_HOST, port=BOT_PORT):
    s = socket.create_connection((host, port), timeout=30)
    s.settimeout(5)
    banner = ""
    while "stamp>" not in banner:
        try:
            chunk = s.recv(4096)
        except TimeoutError:
            break
        if not chunk:
            break
        banner += chunk.decode(errors="replace")
    m = re.search(r"hashcash -mb(\d+) ([0-9a-f]+)", banner)
    if not m:
        raise RuntimeError(f"unexpected bot banner: {banner!r}")
    bits = int(m.group(1))
    resource = m.group(2)
    stamp = solve_pow(resource, bits)
    s.sendall((stamp + "\n").encode())
    data = ""
    while "uuid" not in data.lower():
        try:
            chunk = s.recv(4096)
        except TimeoutError:
            break
        if not chunk:
            break
        data += chunk.decode(errors="replace")
    s.sendall((uuid + "\n").encode())
    out = data
    while True:
        try:
            chunk = s.recv(4096)
        except TimeoutError:
            break
        if not chunk:
            break
        out += chunk.decode(errors="replace")
    s.close()
    return banner + out


def cmd_root(_args):
    r = requests.get(BASE, timeout=30)
    print(r.text)
    print(r.status_code)
    print(r.headers)


def cmd_path(args):
    r = requests.get(BASE + args.path, timeout=30)
    sys.stdout.write(r.text)


def cmd_fetch(args):
    r = requests.get(args.url, timeout=30)
    sys.stdout.write(r.text)


def cmd_register(args):
    c = Client(args.base)
    username = args.username or randstr("user_")
    password = args.password or randstr("pass_")
    print(json.dumps({"username": username, "password": password}, indent=2))
    print(json.dumps(c.register(username, password), indent=2))


def cmd_note(args):
    c = Client(args.base)
    c.register(args.username, args.password)
    note = c.create_note(args.title, Path(args.content_file).read_text(), args.public)
    print(json.dumps(note, indent=2))


def cmd_upload(args):
    c = Client(args.base)
    c.register(args.username, args.password)
    out = c.upload_video(args.file, args.mime)
    print(json.dumps(out, indent=2))


def cmd_runtime(args):
    rc, err, out = raw_tls_get(args.ip, args.host, args.path)
    if getattr(args, "out", None):
        Path(args.out).write_text(out)
    if err:
        print(err, file=sys.stderr)
    print(out)
    sys.exit(0 if rc == 0 else rc)


def cmd_probe_video(args):
    c = Client(args.base)
    username = args.username or randstr("up_")
    password = args.password or randstr("pw_")
    c.register(username, password)
    upload = c.upload_video(args.file, args.mime)
    video_id = upload["id"]
    print(json.dumps({"username": username, "password": password, "id": video_id}, indent=2))
    for path in [
        f"/player/video/{video_id}",
        f"/player/{video_id}.json",
        f"/player/video/{video_id}.json",
        f"/video/{video_id}",
    ]:
        print(f"\n=== {path} ===")
        _, err, out = raw_tls_get(args.ip, args.host, path)
        if err:
            print(err, file=sys.stderr)
        print(out[:8000])


def cmd_bot(args):
    print(bot_visit(args.uuid, args.host, args.port))


def main():
    ap = argparse.ArgumentParser()
    sub = ap.add_subparsers(dest="cmd")

    p = sub.add_parser("root")
    p.set_defaults(func=cmd_root)

    p = sub.add_parser("path")
    p.add_argument("path")
    p.set_defaults(func=cmd_path)

    p = sub.add_parser("fetch")
    p.add_argument("url")
    p.set_defaults(func=cmd_fetch)

    p = sub.add_parser("register")
    p.add_argument("--base", default=BASE)
    p.add_argument("--username")
    p.add_argument("--password")
    p.set_defaults(func=cmd_register)

    p = sub.add_parser("note")
    p.add_argument("--base", default=BASE)
    p.add_argument("--username", required=True)
    p.add_argument("--password", required=True)
    p.add_argument("--title", required=True)
    p.add_argument("--content-file", required=True)
    p.add_argument("--public", action="store_true")
    p.set_defaults(func=cmd_note)

    p = sub.add_parser("upload")
    p.add_argument("--base", default=BASE)
    p.add_argument("--username", required=True)
    p.add_argument("--password", required=True)
    p.add_argument("--file", required=True)
    p.add_argument("--mime", default="video/mp4")
    p.set_defaults(func=cmd_upload)

    p = sub.add_parser("runtime")
    p.add_argument("--ip", required=True)
    p.add_argument("--host", required=True)
    p.add_argument("--out")
    p.add_argument("path")
    p.set_defaults(func=cmd_runtime)

    p = sub.add_parser("probe-video")
    p.add_argument("--base", default=BASE)
    p.add_argument("--host", default="runtime.video.cloud.yandex.net")
    p.add_argument("--ip", default="51.250.1.251")
    p.add_argument("--username")
    p.add_argument("--password")
    p.add_argument("--file", required=True)
    p.add_argument("--mime", default="video/mp4")
    p.set_defaults(func=cmd_probe_video)

    p = sub.add_parser("bot")
    p.add_argument("uuid")
    p.add_argument("--host", default=BOT_HOST)
    p.add_argument("--port", type=int, default=BOT_PORT)
    p.set_defaults(func=cmd_bot)

    args = ap.parse_args()
    if not args.cmd:
        args = ap.parse_args(["root"])
    args.func(args)


if __name__ == "__main__":
    main()
