# DLL Hijacking Lab

Educational project demonstrating DLL search order hijacking on Windows.
Built as a controlled lab environment covering attack, detection, and prevention.

---

## What is DLL Hijacking

Windows loads DLLs by searching locations in order:
1. Application directory
2. System directories (C:\Windows\System32)
3. PATH directories

If a malicious DLL with the correct name is placed in the application
directory, Windows loads it before the legitimate system DLL.
The attacker gains code execution without modifying the target executable.

---

## Project Structure

```
dll-hijack-lab/
├── victim/          # Target executable — imports version.dll
├── fake-dll/        # Malicious version.dll with proxy forwarding
├── detector/        # Runtime scanner — detects hijacked DLLs in running process
└── static-scan/     # Static scanner — detects vulnerable imports before execution
```

---

## Build

Requires GCC (MinGW-w64), windres, make.

```bash
make        # builds all four components
make clean  # cleans all
```

---

## Usage

### Stage 1 — Confirm victim loads version.dll

```bash
cd victim
make
objdump -p victim.exe | grep -i version
```

Expected: `VERSION.dll` in import table.

---

### Stage 2 — Deploy hijack

```bash
cd fake-dll
make
copy version.dll ..\victim\version.dll
cd ..\victim
victim.exe
type C:\Users\Public\hijack_proof.txt
```

Expected: `HIJACKED` written to proof file.
Victim still runs normally — hijack masked via proxy forwarding.

---

### Stage 3 — Detect with runtime scanner

Run victim.exe in one terminal, keep it open.

```bash
cd detector
make
detector.exe victim.exe
```

Expected output:
```
[SUSPICIOUS] ...\victim\version.dll
             ^ non-system path
             ^ unsigned
```

---

### Stage 4 — Detect with static scanner

Fake DLL still in victim folder:
```bash
cd static-scan
make
static_scan.exe ..\victim\victim.exe
```

Expected:
```
[VULNERABLE] VERSION.dll
             ^ shadowed at: ...\victim\version.dll
```

Remove fake DLL, scan again:
```bash
del ..\victim\version.dll
static_scan.exe ..\victim\victim.exe
```

Expected:
```
[SAFE] VERSION.dll
```

---

### Stage 5 — Prevention

Victim uses `LoadLibraryExA` with `LOAD_LIBRARY_SEARCH_SYSTEM32` flag.
Forces Windows to load version.dll from System32 only — ignores application folder.

```bash
del C:\Users\Public\hijack_proof.txt
cd victim
victim.exe
type C:\Users\Public\hijack_proof.txt
```

Expected: file missing or unchanged — hijack never fired.

---

## Key Concepts Demonstrated

| Concept | Where |
|---------|-------|
| DLL search order hijacking | fake-dll + victim |
| DLL proxying / export forwarding | fake-dll/dllmain.c |
| PE import table parsing | static-scan/main.c |
| Runtime process module enumeration | detector/main.c |
| WinVerifyTrust signature checking | detector/main.c |
| LoadLibraryEx safe loading | victim/main.c |

---

## Tools Used

- GCC / MinGW-w64
- Sysinternals Process Monitor (runtime verification)
- objdump (import table inspection)

---

## Disclaimer

Built for educational purposes in a controlled environment.
Demonstrates MITRE ATT&CK T1574.001 — DLL Search Order Hijacking.
