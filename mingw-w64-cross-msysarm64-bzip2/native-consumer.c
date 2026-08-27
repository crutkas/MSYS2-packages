#define WINVER 0x0A00
#define _WIN32_WINNT 0x0A00

#include <bzlib.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <windows.h>
#include <tlhelp32.h>

enum {
  THREAD_COUNT = 4,
  INPUT_SIZE = 1024 * 1024
};

static DWORD WINAPI
roundtrip(void *context)
{
  unsigned int seed = (unsigned int)(uintptr_t)context;
  unsigned int input_size = INPUT_SIZE;
  unsigned int compressed_size = INPUT_SIZE + INPUT_SIZE / 100 + 601;
  unsigned int output_size = INPUT_SIZE;
  char *input = malloc(input_size);
  char *compressed = malloc(compressed_size);
  char *output = malloc(output_size);
  int result = 1;
  unsigned int index;

  if (input == NULL || compressed == NULL || output == NULL)
    goto done;
  for (index = 0; index < input_size; ++index)
    input[index] = (char)((index * 33u + seed * 17u) & 0xffu);

  if (BZ2_bzBuffToBuffCompress(compressed, &compressed_size, input,
                              input_size, 9, 0, 30) != BZ_OK)
    goto done;
  if (BZ2_bzBuffToBuffDecompress(output, &output_size, compressed,
                                compressed_size, 0, 0) != BZ_OK)
    goto done;
  if (output_size != input_size || memcmp(input, output, input_size) != 0)
    goto done;

  compressed[compressed_size / 2] ^= 0x40;
  output_size = INPUT_SIZE;
  if (BZ2_bzBuffToBuffDecompress(output, &output_size, compressed,
                                compressed_size, 0, 0) == BZ_OK)
    goto done;
  result = 0;

done:
  free(output);
  free(compressed);
  free(input);
  return (DWORD)result;
}

static int
print_modules(void)
{
  MODULEENTRY32 entry;
  HANDLE snapshot;

  snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, GetCurrentProcessId());
  if (snapshot == INVALID_HANDLE_VALUE)
    return 1;
  memset(&entry, 0, sizeof(entry));
  entry.dwSize = sizeof(entry);
  if (!Module32First(snapshot, &entry)) {
    CloseHandle(snapshot);
    return 2;
  }
  do {
    printf("module=%s\tpath=%s\n", entry.szModule, entry.szExePath);
  } while (Module32Next(snapshot, &entry));
  CloseHandle(snapshot);
  return 0;
}

int
main(void)
{
  HANDLE threads[THREAD_COUNT];
  USHORT process_machine = 0;
  USHORT native_machine = 0;
  DWORD exit_code;
  int index;

  if (!IsWow64Process2(GetCurrentProcess(), &process_machine, &native_machine))
    return 10;
  printf("process_machine=0x%04x\tnative_machine=0x%04x\n",
         process_machine, native_machine);
  printf("bzlib_version=%s\n", BZ2_bzlibVersion());

  for (index = 0; index < THREAD_COUNT; ++index) {
    threads[index] = CreateThread(NULL, 0, roundtrip,
                                  (void *)(uintptr_t)(index + 1), 0, NULL);
    if (threads[index] == NULL)
      return 20 + index;
  }
  if (WaitForMultipleObjects(THREAD_COUNT, threads, TRUE, INFINITE) !=
      WAIT_OBJECT_0)
    return 30;
  for (index = 0; index < THREAD_COUNT; ++index) {
    if (!GetExitCodeThread(threads[index], &exit_code) || exit_code != 0)
      return 40 + index;
    CloseHandle(threads[index]);
  }
  if (print_modules() != 0)
    return 50;
  puts("threaded_roundtrip=ok");
  return 0;
}
