#include <excpt.h>
#include <windows.h>

#ifndef __aarch64__
#error "The target compiler must define __aarch64__"
#endif
#ifndef _WIN64
#error "The target compiler must define _WIN64"
#endif

_Static_assert(sizeof(long) == 8, "Cygwin uses LP64");
_Static_assert(sizeof(LONG) == 4, "The Windows API uses 32-bit LONG");
_Static_assert(sizeof(void *) == 8, "Windows ARM64 pointers are 64-bit");

EXCEPTION_DISPOSITION
w32api_probe(struct _EXCEPTION_RECORD *record, void *frame,
             struct _CONTEXT *context, struct _DISPATCHER_CONTEXT *dispatcher)
{
  return __C_specific_handler(record, frame, context, dispatcher);
}
