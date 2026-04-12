<div align="center">

# Noisy Vault — HackTheBox

![Difficulty](https://img.shields.io/badge/Difficulty-Easy-green?style=for-the-badge)
![Category](https://img.shields.io/badge/Category-Quantum-purple?style=for-the-badge)
![Status](https://img.shields.io/badge/Status-Solved-success?style=for-the-badge)

<img src="../../assets/MrsNobody.png" width="200" alt="MrsNobody">

**MrsNobody**

---

</div>

> **Disclaimer:** This writeup is for educational purposes only, performed in an authorized Hack The Box environment.

## Challenge Information

| Property | Value |
|----------|-------|
| Challenge | Noisy Vault |
| Category | Quantum |
| Difficulty | Easy |
| Points | 30 |
| Creator | Hunntr |
| Type | TCP Service + Downloadable Source |

---

## Table of Contents

1. [Scenario](#scenario)
2. [Reconnaissance](#reconnaissance)
3. [Source Code Analysis](#source-code-analysis)
4. [Understanding the Quantum System](#understanding-the-quantum-system)
5. [Building the Solution](#building-the-solution)
6. [Exploit Script](#exploit-script)
7. [Flag](#flag)
8. [Key Takeaways](#key-takeaways)

---

## Scenario

> The city's central vault is shielded by a 13-qubit quantum processor. The 9-bit access code is rapidly decaying due to constant decoherence. Use the available ancilla qubits to mitigate the noise and stabilize the signal. You have one shot at the key before the security lockdown engages. Can you filter the truth from the noise?

---

## Reconnaissance

### Connect to the Service

```bash
nc <CHALLENGE_IP> <PORT>
```

```
    ╔══════════════════════════════════════════╗
    ║                NOISY VAULT               ║
    ╚══════════════════════════════════════════╝
    Status: SECURE - Random rotation key engaged
    Warning: Only ONE attempt to unlock

1. Access Quantum Oracle (Single Query)
2. Enter Vault Access Code (One-Shot)
3. Exit
```

The service provides:
- **One oracle query** — submit a quantum circuit, get measurement results (4096 shots)
- **One unlock attempt** — submit the 64-bit secret key

### Download and Extract Source

```bash
unzip -P hackthebox Noisy_Vault.zip
```

---

## Source Code Analysis

### The Vault Setup (`server.py`)

```python
class Vault:
    def __init__(self):
        self.visible_bits = 64
        self.secret_key = bin(secrets.randbits(self.visible_bits))[2:].zfill(self.visible_bits)
        self.total_data_qubits = 64      # Qubits 0-63
        self.ancilla_qubits = 16         # Qubits 64-79
        self.total_qubits = 80
        self.shots = 4096
        self.idle_cycles = 6
        self.max_oracle_calls = 1
```

### Noise Model

```python
noise.add_all_qubit_quantum_error(depolarizing_error(0.008, 1), [...single gates...])
noise.add_all_qubit_quantum_error(depolarizing_error(0.02, 2), ["cx", "cz", "swap"])
noise.add_all_qubit_quantum_error(depolarizing_error(0.02, 1), ["measure"])
```

- 0.8% single-qubit depolarizing error
- 2% two-qubit depolarizing error
- 2% measurement error
- 6 idle cycles (each qubit gets a noisy identity gate per cycle)

### Oracle Flow

1. Prepare secret key as quantum state (X gate on qubits where bit = 1)
2. Apply your corrective circuit
3. Apply 6 idle cycles (noise accumulation)
4. Measure all 64 data qubits, 4096 times
5. Return measurement counts

### Circuit Validation Requirements

```python
self.min_data_ancilla_links = 16    # At least 16 CX-type gates between data and ancilla
self.min_active_ancillas = 4        # At least 4 ancilla qubits must be used
self.max_circuit_ops = 512          # Max 512 operations
```

The validation is performed on the **compiled** circuit (optimization_level=3), so trivially-cancelling gate pairs are optimized away.

---

## Understanding the Quantum System

The secret key is encoded as a **computational basis state** — each qubit is simply |0> or |1>. The noise model adds random bit-flip errors with a per-bit error rate of roughly 5-8% (from gate errors + idle cycles + measurement errors).

With 4096 measurement shots, each bit position will show the **correct value in the majority of measurements**, even with noise. The strategy is simple: **majority voting per bit**.

### Why the Circuit Constraint Exists

The challenge requires your circuit to actually use ancilla qubits (min 16 data-ancilla links, min 4 active ancillas). This prevents submitting an empty circuit. The solution: use CNOT gates from data qubits to ancillas — this satisfies the constraint without destroying the data qubit states.

### Circuit Design

```
CX:0,64; CX:1,65; CX:2,66; ... CX:15,79
```

This applies 16 CNOT gates, each connecting one data qubit (0-15) to one ancilla qubit (64-79). The CNOT copies the data qubit's value to the ancilla but does NOT change the data qubit. Since only the 64 data qubits are measured, the ancillas don't affect the output.

---

## Building the Solution

### Step 1: Connect and Send Circuit

```python
circuit_parts = [f"CX:{i},{64+i}" for i in range(16)]
circuit = ";".join(circuit_parts)
# Result: CX:0,64;CX:1,65;CX:2,66;...;CX:15,79
```

### Step 2: Parse Measurement Results

The oracle returns a JSON dictionary of bitstring counts:

```json
{"1100111100011111...": 3, "0100111100011111...": 1, ...}
```

### Step 3: Majority Voting

For each of the 64 bit positions, count how many times it was measured as 0 vs 1 across all 4096 shots. The majority wins.

```python
for bitstring, count in counts.items():
    for i in range(64):
        bit_val = int(bitstring[63 - i])  # Qiskit: rightmost = qubit 0
        bit_counts[i][bit_val] += count

key = ""
for i in range(64):
    key += "1" if bit_counts[i][1] > bit_counts[i][0] else "0"
```

---

## Exploit Script

```python
#!/usr/bin/env python3
import socket, json, re

HOST = "<CHALLENGE_IP>"
PORT = 30569  # Replace with actual port

def recv_until(s, prompt, timeout=120):
    s.settimeout(timeout)
    data = b""
    while True:
        try:
            chunk = s.recv(4096)
            if not chunk: break
            data += chunk
            if prompt.encode() in data: break
        except socket.timeout: break
    return data.decode()

def send(s, msg):
    s.sendall((msg + "\n").encode())

# Build circuit: CX from data[i] to ancilla[i] for 16 pairs
circuit = ";".join([f"CX:{i},{64+i}" for i in range(16)])

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect((HOST, PORT))

recv_until(s, "Choice > ")
send(s, "1")
recv_until(s, "> ", timeout=30)

# Send circuit and wait for simulation
send(s, circuit)
data = recv_until(s, "Choice > ", timeout=180)

# Extract results
match = re.search(r'Results:\s*(\{.*?\})', data, re.DOTALL)
counts = json.loads(match.group(1))

# Majority voting per bit
num_bits = 64
bit_counts = [[0, 0] for _ in range(num_bits)]
for bitstring, count in counts.items():
    for i in range(num_bits):
        bit_val = int(bitstring[num_bits - 1 - i])
        bit_counts[i][bit_val] += count

key = "".join("1" if bc[1] > bc[0] else "0" for bc in bit_counts)
print(f"[*] Recovered key: {key}")

# Submit the key
send(s, "2")
recv_until(s, "> ", timeout=10)
send(s, key)

s.settimeout(10)
print(s.recv(8192).decode())
s.close()
```

### Running the Exploit

```bash
python3 solve_vault.py
```

```
[*] Recovered key: 1100111100011111000010110100000111001101001101010110111101111000
[+] Access Granted! The vault opens: HTB{Qu4nTUm_n01s3_c4nt_st0p_th3_v4ult_h4ck!}
```

---

## Flag

| Flag | Value |
|------|-------|
| Challenge | `HTB{Qu4nTUm_n01s3_c4nt_st0p_████████████████████}` |

---

## Key Takeaways

- **Quantum noise** in computational basis measurements is analogous to a noisy binary channel — majority voting is an effective classical error correction strategy
- With 4096 measurement shots and ~5-8% per-bit error rate, the correct bit value appears in >90% of measurements — majority voting recovers the key with near-perfect accuracy
- The ancilla qubit constraint is a red herring — the challenge wants you to use them for "error correction," but simple CNOT coupling satisfies validation without actually needing sophisticated quantum error correction codes
- **Qiskit** measurement bitstrings are in **reverse order** (qubit 0 = rightmost) — a common gotcha in quantum computing CTFs
- Understanding the noise model parameters (depolarizing error rates, idle cycles) helps estimate whether majority voting will work before attempting the single-shot unlock

---

<div align="center">

**Written by MrsNobody**

<img src="../../assets/MrsNobody.png" width="80">

*Hack The Box — Noisy Vault*

</div>

<!-- HTB Noisy Vault Search Keywords -->
<!-- noisy vault hackthebox, noisy vault htb, noisy vault htb writeup, noisy vault htb walkthrough -->
<!-- quantum computing ctf, qiskit challenge, quantum error correction ctf, quantum oracle -->
<!-- depolarizing noise, majority voting quantum, quantum key recovery, ancilla qubits -->
<!-- htb easy quantum challenge, hackthebox quantum, 13 qubit quantum processor ctf -->
