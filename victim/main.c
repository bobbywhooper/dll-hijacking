/**
 * This is a simple victim program that loads version.dll and calls
 * GetFileVersionInfoSizeA() on itself. It is used to demonstrate DLL hijacking.
 *
 * Compile with:
 *   gcc -o victim.exe main.c -lversion
 *
 * Run with:
 *   victim.exe
 *
 * If you run this in the same folder as a malicious version.dll, it will load
 * the malicious DLL instead of the real one from System32.
 *
 * To avoid this, we can explicitly load the real version.dll from System32 using
 * LoadLibraryExA() with LOAD_LIBRARY_SEARCH_SYSTEM32.
 *
 * Compile with:
 *   gcc -o victim.exe main.c -lversion
 *
 * Run with:
 *   victim.exe
 *
 * This will load the real version.dll from System32, even if a malicious version.dll
 * is present in the same folder.
 

#include <windows.h>
#include <stdio.h>

int main() {
    char filename[MAX_PATH];
    GetModuleFileNameA(NULL, filename, MAX_PATH);

    DWORD dummy;
    DWORD size = GetFileVersionInfoSizeA(filename, &dummy);

    if (size == 0) {
        printf("No version info found — but version.dll still loaded!\n");
    } else {
        printf("Version info size: %lu bytes\n", size);
    }

    printf("Press Enter to exit...\n");
    getchar(); // keeps process alive so procmon can inspect it
    return 0;
}
**/

#include <windows.h>
#include <stdio.h>

int main() {
    // load version.dll from System32 ONLY — ignores app folder
    HMODULE ver = LoadLibraryExA(
        "version.dll",
        NULL,
        LOAD_LIBRARY_SEARCH_SYSTEM32
    );

    if (!ver) {
        printf("Failed to load version.dll\n");
        return 1;
    }

    // get function from explicitly loaded real DLL
    typedef DWORD (WINAPI *GetFileVersionInfoSizeA_t)(LPCSTR, LPDWORD);
    GetFileVersionInfoSizeA_t fn = (GetFileVersionInfoSizeA_t)
        GetProcAddress(ver, "GetFileVersionInfoSizeA");

    char filename[MAX_PATH];
    GetModuleFileNameA(NULL, filename, MAX_PATH);

    DWORD dummy;
    DWORD size = fn(filename, &dummy);

    if (size == 0) {
        printf("No version info — but loaded safely from System32\n");
    } else {
        printf("Version info size: %lu bytes\n", size);
    }

    printf("Press Enter to exit...\n");
    getchar();

    FreeLibrary(ver);
    return 0;
}