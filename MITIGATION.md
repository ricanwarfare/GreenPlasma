# GreenPlasma — Mitigation & Hardening Recommendations

## Vulnerability Summary

GreenPlasma exploits a logic bug in `ctfmon.exe` where it creates section objects without validating that the target path is a symbolic link. This allows a standard user to redirect SYSTEM-trusted section creation to an attacker-controlled path, leading to local privilege escalation.

---

## Microsoft Recommended Fix

### 1. Symlink Validation in ctfmon.exe
**Priority: Critical**

`ctfmon.exe` must check for existing symbolic links at the target path before calling `NtCreateSection`. If a symlink exists, ctfmon should:
- Refuse to create the section
- Log the event
- Fall back to a non-linkable namespace path

```c
// Pseudocode fix:
NTSTATUS status = NtCreateSection(...);
if (status == STATUS_OBJECT_NAME_COLLISION || IsSymbolicLink(targetPath)) {
    LogSecurityEvent(EVENT_CTFMON_SYMLINK_DETECTED);
    return STATUS_ACCESS_DENIED;
}
```

### 2. Registry Symlink Restrictions
**Priority: High**

The Cloud Files policy engine should not follow registry symbolic links when evaluating `BlockedApps` policy. Add a flag to `CfAbortOperation` and related APIs to reject symlink targets.

### 3. Section Object Protection
**Priority: High**

When `ctfmon` creates the `CTF.AsmListCache` section, it should:
- Set a restrictive DACL (only SYSTEM and the session owner)
- Set `SEC_COMMIT` instead of `SEC_IMAGE` to prevent code execution from the section
- Use `NtCreateSectionEx` with `SECTION_MAP_EXECUTE` explicitly denied

---

## Enterprise Hardening (Immediate)

### Group Policy: Disable CTFMON Section Creation
If your environment doesn't rely on Text Services Framework features (speech recognition, handwriting, input method editors), consider disabling ctfmon:

```
Computer Configuration → Administrative Templates → System → 
  "Do not allow CTFMON to create shared memory sections"
```

**Note:** This may break input methods. Test in your environment first.

### Registry Hardening: Protect Policies\System Key
Apply explicit DACL to `HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\System`:
- Remove `Everyone` and `Authenticated Users` write access
- Ensure only `Administrators` and `SYSTEM` can write

```powershell
# Apply restrictive DACL
$acl = Get-Acl "HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\System"
$rule = New-Object System.Security.AccessControl.RegistryAccessRule(
    "Everyone", "ReadKey", "Allow"
)
$acl.AddAccessRule($rule)
# Remove existing Everyone GENERIC_ALL if present
$acl.Access | Where-Object { $_.IdentityReference -eq "Everyone" -and $_.AccessControlType -eq "Allow" } | ForEach-Object {
    $acl.RemoveAccessRule($_)
}
Set-Acl "HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\System" $acl
```

### Object Manager Namespace Protection
Enable namespace isolation for non-admin sessions:

```powershell
# Verify session isolation is enabled
reg query "HKLM\SYSTEM\CurrentControlSet\Session Manager\kernel" /v ObUnsecureGlobalNamespaces
```

If disabled, enable it:
```powershell
reg add "HKLM\SYSTEM\CurrentControlSet\Session Manager\kernel" /v ObUnsecureGlobalNamespaces /t REG_DWORD /d 0 /f
```

### CloudFiles Policy ACL Restrictions
Prevent standard users from modifying Cloud Files policy:

```powershell
# Restrict CloudFiles policy key
$acl = Get-Acl "HKCU:\Software\Policies\Microsoft\CloudFiles"
$rule = New-Object System.Security.AccessControl.RegistryAccessRule(
    "Everyone", "ReadKey", "Allow"
)
$acl.AddAccessRule($rule)
Set-Acl "HKCU:\Software\Policies\Microsoft\CloudFiles" $acl
```

---

## Detection & Monitoring

### Sysmon Configuration
Deploy the Sigma rules in `detection/sigma-greenplasma.yml` via your SIEM. Key events to monitor:

| Event ID | What to Monitor |
|----------|----------------|
| 12 | Registry key creation with `REG_OPTION_CREATE_LINK` |
| 13 | `DisableLockWorkstation = 1` set in HKCU Policies\System |
| 4663 | DACL modification on CloudFiles or Policies\System keys |
| 1 | Unexpected `CfAbortOperation` calls from non-Cloud Files processes |

### EDR Telemetry
Monitor for:
- `NtCreateSymbolicLinkObject` calls targeting `CTF.AsmListCache` paths
- `TreeSetNamedSecurityInfo` with `Everyone: GENERIC_ALL` on registry keys
- `NtMapViewOfSection` on `\Sessions\*\BaseNamedObjects\CTF.AsmListCache*` from non-ctfmon processes

### Process Behavior
- Standard user processes opening handles to `CTF.AsmListCache` sections
- `ctfmon.exe` creating sections outside its expected namespace
- `cldapi.dll` loaded by non-Cloud Files processes

---

## Workarounds (Pre-Patch)

### Workaround 1: Disable CTFMON Startup (Aggressive)
```
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" /v Ctfmon /d "" /f
sc config ctfmon start=disabled
```
**Impact:** Breaks speech recognition, handwriting input, and some IME features.

### Workaround 2: Session 0 Isolation Enforcement
Ensure that interactive applications run only in user sessions, and ctfmon in Session 0 cannot be influenced by user-created symbolic links:
```
gpedit.msc → Computer Configuration → Windows Settings → Security Settings → Local Policies → Security Options → 
  "Interactive logon: Do not require CTRL+ALT+DEL" → Disabled
```

### Workaround 3: Registry Key Protection (Recommended)
Apply OWNER-only DACLs to `HKCU\Software\Policies\Microsoft\CloudFiles` and `HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\System`:
```powershell
$key = [Microsoft.Win32.Registry]::CurrentUser.OpenSubKey("Software\Policies\Microsoft\CloudFiles", "ReadWriteSubTree", "ChangePermissions")
$acl = $key.GetAccessControl()
$acl.SetOwner([System.Security.Principal.NTAccount]"Administrators")
$rule = New-Object System.Security.AccessControl.RegistryAccessRule("Administrators", "FullControl", "ContainerInherit,ObjectInherit", "None", "Allow")
$acl.AddAccessRule($rule)
$key.SetAccessControl($acl)
```

---

## MSRC Submission Checklist

- [ ] Vulnerability type: Elevation of Privilege
- [ ] Affected component: `ctfmon.exe` (Windows Text Services Framework)
- [ ] Attack vector: Local (standard user required)
- [ ] Privileges gained: SYSTEM
- [ ] User interaction required: None
- [ ] Affected versions: Windows 11, Windows Server 2022, Windows Server 2026
- [ ] Reproducibility: 100% (deterministic)
- [ ] PoC provided: Yes (PoC.cpp)
- [ ] Detection rules provided: Yes (sigma-greenplasma.yml)
- [ ] Suggested fix: Symlink validation in ctfmon section creation path