#include <windows.h>
#include <stdio.h>
#include <string.h>

typedef int (*smoke_fn)(void);

int main(int argc, char **argv)
{
    wchar_t path[MAX_PATH];
    HMODULE module;
    smoke_fn smoke;
    DWORD flags = 0;
    int result;

    setvbuf(stdout, NULL, _IONBF, 0);
    setvbuf(stderr, NULL, _IONBF, 0);
    if (argc != 3)
        return 2;
    if (strcmp(argv[2], "dont-resolve") == 0)
        flags = DONT_RESOLVE_DLL_REFERENCES;
    else if (strcmp(argv[2], "normal") != 0)
        return 3;
    if (MultiByteToWideChar(CP_UTF8, 0, argv[1], -1, path, MAX_PATH) == 0)
        return 4;

    puts("loadlibrary-before");
    module = LoadLibraryExW(path, NULL, flags);
    if (module == NULL) {
        fprintf(stderr, "LoadLibraryExW error: %lu\n", GetLastError());
        return 5;
    }
    puts("loadlibrary-after");
    if (flags == 0) {
        smoke = (smoke_fn)GetProcAddress(module, "openssl_dlopen_smoke");
        if (smoke == NULL) {
            fprintf(stderr, "GetProcAddress error: %lu\n", GetLastError());
            FreeLibrary(module);
            return 6;
        }
        puts("getprocaddress-after");
        result = smoke();
        puts("callback-after");
        if (result != 42) {
            FreeLibrary(module);
            return 7;
        }
    }
    puts("freelibrary-before");
    if (!FreeLibrary(module))
        return 8;
    puts("freelibrary-after");
    puts("loadlibrary-smoke=pass");
    return 0;
}
