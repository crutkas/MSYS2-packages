#include <reent.h>
#include <stdint.h>
#include <sys/cygwin.h>
#include <windows.h>

static_assert(sizeof(long) == 8, "Cygwin must remain LP64");
static_assert(sizeof(void *) == 8, "Cygwin pointers must remain 64-bit");
static_assert(sizeof(LONG) == 4, "Windows LONG must remain 32-bit");
static_assert(sizeof(ULONG_PTR) == 8, "ULONG_PTR must follow pointer width");

extern "C" uintptr_t
sysroot_cxx_probe(_reent *reent, HANDLE handle)
{
  return reinterpret_cast<uintptr_t>(handle)
         + static_cast<uintptr_t>(reent->_errno);
}
