#include <windows.h>

static void write_marker(const char *name, const char *message)
{
    HANDLE marker;
    DWORD written;

    marker = CreateFileA(name,
                         GENERIC_WRITE,
                         FILE_SHARE_READ,
                         NULL,
                         CREATE_ALWAYS,
                         FILE_ATTRIBUTE_NORMAL,
                         NULL);
    if (marker != INVALID_HANDLE_VALUE) {
        WriteFile(marker, message, lstrlenA(message), &written, NULL);
        CloseHandle(marker);
    }
}

BOOL WINAPI DllMain(HINSTANCE instance, DWORD reason, LPVOID reserved)
{
    (void)instance;
    (void)reserved;
    if (reason == DLL_PROCESS_ATTACH)
        write_marker("dllmain-attached.marker", "dllmain-process-attach\n");
    else if (reason == DLL_PROCESS_DETACH)
        write_marker("dllmain-detached.marker", "dllmain-process-detach\n");
    return TRUE;
}

__declspec(dllexport) int openssl_dlopen_smoke(void)
{
    return 42;
}
