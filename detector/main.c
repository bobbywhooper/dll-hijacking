#include <windows.h> // windows functions and data types
#include <tlhelp32.h> // tools for looking through running processes and threads
#include <psapi.h> // tools for inspecting processes and modules
#include <wintrust.h> // digital signature verification
#include <stdio.h> // standard input/output functions 
#include <ctype.h> // character handling
#include <string.h> // string manipulation functions and data types

// GUID (Globally Unique Identifier) 
// identifies the Microsoft Authenticode signature verification
static GUID auth_guid = {
    0x00AAC56B, 0xCD44, 0x11d0, 
    { 0x8C, 0xC2, 0x00, 0xC0, 0x4F, 0xC2, 0x95, 0xEE }
};

int is_system_path(const char* path) {
    // Check if the path starts with "C:\Windows" or "C:\Program Files"
    char sysdir[MAX_PATH];
    GetSystemDirectoryA(sysdir, MAX_PATH);

    // lowercase both for comparison
    char p[MAX_PATH], s[MAX_PATH];
    strncpy(p, path, MAX_PATH);
    strncpy(s, sysdir, MAX_PATH);
    for (int i = 0; p[i]; i++) p[i] = tolower(p[i]);
    for (int i = 0; s[i]; i++) s[i] = tolower(s[i]);

    return (strncmp(p, s, strlen(s)) == 0);
}

// ─── FUNCTION 2: is_signed ────────────────────────────────
// asks Windows to verify digital signature of a file
int is_signed(const char* path) {
    WCHAR wide[MAX_PATH];
    MultiByteToWideChar(CP_UTF8, 0, path, -1, wide, MAX_PATH);

    WINTRUST_FILE_INFO file_info = { 0 };
    file_info.cbStruct = sizeof(file_info);
    file_info.pcwszFilePath = wide;
    file_info.hFile = NULL;
    file_info.pgKnownSubject = NULL;

    WINTRUST_DATA wintrust_data = { 0 };
    wintrust_data.cbStruct = sizeof(wintrust_data);
    wintrust_data.dwUIChoice = WTD_UI_NONE;
    wintrust_data.fdwRevocationChecks = WTD_REVOKE_NONE;
    wintrust_data.dwUnionChoice = WTD_CHOICE_FILE;
    wintrust_data.pFile = &file_info;
    wintrust_data.dwStateAction = WTD_STATEACTION_VERIFY;

    LONG status = WinVerifyTrust(NULL, &auth_guid, &wintrust_data);

    // Clean up
    wintrust_data.dwStateAction = WTD_STATEACTION_CLOSE;
    WinVerifyTrust(NULL, &auth_guid, &wintrust_data);

    return (status == ERROR_SUCCESS);
}

// ─── FUNCTION 3: find_pid ─────────────────────────────────
// finds process ID from process name
DWORD find_pid(const char* process_name) {
    DWORD pid = 0;
    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snapshot == INVALID_HANDLE_VALUE) {
        return 0;
    }

    PROCESSENTRY32 pe;
    pe.dwSize = sizeof(PROCESSENTRY32);

    if (Process32First(snapshot, &pe)) {
        do {
            if (_stricmp(pe.szExeFile, process_name) == 0) {
                pid = pe.th32ProcessID;
                break;
            }
        } while (Process32Next(snapshot, &pe));
    }

    CloseHandle(snapshot);
    return pid;
}

// ─── MAIN SCANNER ─────────────────────────────────────────
void scan(const char* proc_name) {
    printf("[DETECTOR] Looking for: %s\n\n", proc_name);

    DWORD pid = find_pid(proc_name);
    if (!pid) {
        printf("[ERROR] Process not found. Is it running?\n");
        return;
    }

    printf("[SCANNING] %s (PID: %lu)\n\n", proc_name, pid);

    HANDLE proc = OpenProcess(
        PROCESS_QUERY_INFORMATION | PROCESS_VM_READ,
        FALSE, pid
    );
    if (!proc) {
        printf("[ERROR] Access denied. Run detector as Administrator.\n");
        return;
    }

    HMODULE mods[1024];
    DWORD   needed;
    EnumProcessModules(proc, mods, sizeof(mods), &needed);

    int total      = needed / sizeof(HMODULE);
    int suspicious = 0;

    for (int i = 0; i < total; i++) {
        char path[MAX_PATH];
        if (!GetModuleFileNameExA(proc, mods[i], path, MAX_PATH)) continue;

        int sys    = is_system_path(path);
        int signed_ = is_signed(path);

        if (!sys || !signed_) {
            printf("[SUSPICIOUS] %s\n", path);
            if (!sys)    printf("             ^ non-system path\n");
            if (!signed_) printf("             ^ unsigned\n");
            suspicious++;
        } else {
            printf("[OK]         %s\n", path);
        }
    }

    printf("\n[RESULT] %d suspicious DLL(s) out of %d loaded.\n",
           suspicious, total);

    CloseHandle(proc);
}

int main(int argc, char* argv[]) {
    if (argc < 2) {
        printf("Usage: detector.exe <process_name.exe>\n");
        return 1;
    }
    scan(argv[1]);
    return 0;
}