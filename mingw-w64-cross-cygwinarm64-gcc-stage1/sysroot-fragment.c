#include <reent.h>
#include <stdint.h>
#include <sys/cygwin.h>
#include <sys/types.h>
#include <windows.h>

_Static_assert(sizeof(long) == 8, "Cygwin must remain LP64");
_Static_assert(sizeof(void *) == 8, "Cygwin pointers must remain 64-bit");
_Static_assert(sizeof(LONG) == 4, "Windows LONG must remain 32-bit");
_Static_assert(sizeof(DWORD) == 4, "Windows DWORD must remain 32-bit");
_Static_assert(sizeof(LONG_PTR) == 8, "LONG_PTR must follow pointer width");
_Static_assert(sizeof(ULONG_PTR) == 8, "ULONG_PTR must follow pointer width");

uintptr_t
sysroot_c_probe(struct _reent *reent, HANDLE handle)
{
  return (uintptr_t) handle + (uintptr_t) reent->_errno;
}
