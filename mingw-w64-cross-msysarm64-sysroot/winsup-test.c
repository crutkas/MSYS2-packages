#include <cygwin/version.h>
#include <pthread.h>
#include <sys/cygwin.h>
#include <sys/utsname.h>

#ifndef __CYGWIN__
#error "The target compiler must define __CYGWIN__"
#endif

_Static_assert(sizeof(pthread_t) == sizeof(void *), "pthread_t is pointer-sized");

int
winsup_probe(struct utsname *name)
{
  return uname(name);
}
