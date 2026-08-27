#include <windows.h>

BOOL WINAPI DllMain(HINSTANCE instance, DWORD reason, LPVOID reserved)
{
    HANDLE marker;
    DWORD written;
    static const char message[] = "dllmain-process-attach\n";

    (void)instance;
    (void)reserved;
    if (reason == DLL_PROCESS_ATTACH) {
        marker = CreateFileA("dllmain-attached.marker",
                             GENERIC_WRITE,
                             FILE_SHARE_READ,
                             NULL,
                             CREATE_ALWAYS,
                             FILE_ATTRIBUTE_NORMAL,
                             NULL);
        if (marker != INVALID_HANDLE_VALUE) {
            WriteFile(marker, message, sizeof(message) - 1, &written, NULL);
            CloseHandle(marker);
        }
    }
    return TRUE;
}

__declspec(dllexport) int openssl_dlopen_smoke(void)
{
    return 42;
}
