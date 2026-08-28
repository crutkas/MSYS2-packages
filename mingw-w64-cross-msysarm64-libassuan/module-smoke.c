#define WIN32_LEAN_AND_MEAN
#include <windows.h>

#include <assuan.h>
#include <stdio.h>
#include <string.h>
#include <wchar.h>

static int
check_module (const wchar_t *name)
{
  wchar_t path[MAX_PATH];
  const wchar_t *base;
  HMODULE module;
  DWORD length;

  module = GetModuleHandleW (name);
  if (!module)
    {
      fwprintf (stderr, L"module is not loaded: %ls\n", name);
      return 1;
    }
  length = GetModuleFileNameW (module, path, MAX_PATH);
  if (!length || length == MAX_PATH)
    {
      fwprintf (stderr, L"module path is unavailable: %ls\n", name);
      return 1;
    }
  base = wcsrchr (path, L'\\');
  base = base ? base + 1 : path;
  if (CompareStringOrdinal (base, -1, name, -1, TRUE) != CSTR_EQUAL)
    {
      fwprintf (stderr, L"unexpected module basename: %ls\n", path);
      return 1;
    }
  wprintf (L"%ls=%ls\n", name, path);
  return 0;
}

int
main (void)
{
  SYSTEM_INFO system_info;
  const char *version;

  version = assuan_check_version (NULL);
  if (!version || strcmp (version, "3.0.2"))
    {
      fprintf (stderr, "unexpected libassuan version\n");
      return 1;
    }

  GetNativeSystemInfo (&system_info);
  if (system_info.wProcessorArchitecture != PROCESSOR_ARCHITECTURE_ARM64)
    {
      fprintf (stderr, "process is not running on native ARM64 Windows\n");
      return 1;
    }

  if (check_module (L"msys-2.0.dll")
      || check_module (L"msys-gpg-error-0.dll")
      || check_module (L"msys-assuan-9.dll"))
    return 1;

  printf ("native ARM64 libassuan process/module proof passed\n");
  return 0;
}
