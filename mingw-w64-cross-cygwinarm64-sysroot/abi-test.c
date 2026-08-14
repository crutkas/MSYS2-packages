#include <stdint.h>

_Thread_local uintptr_t cygwin_tls_probe;

extern int external_probe(uintptr_t);

int
abi_probe(uintptr_t value)
{
  volatile uintptr_t unwind_frame[8] = {value};
  cygwin_tls_probe += unwind_frame[0];
  return external_probe(cygwin_tls_probe);
}
