#include <windows.h>
#include <winternl.h>

void
mainCRTStartup(void)
{
  HANDLE event = CreateEventW(NULL, FALSE, FALSE, NULL);

  if (event != NULL)
    NtClose(event);

  ExitProcess(0);
}
