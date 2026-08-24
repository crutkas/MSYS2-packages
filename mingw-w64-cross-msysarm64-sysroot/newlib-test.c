#include <newlib.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

#ifndef _LDBL_EQ_DBL
#error "AArch64 MSYS requires 64-bit long double"
#endif

_Static_assert(sizeof(long) == 8, "MSYS uses LP64");
_Static_assert(sizeof(void *) == 8, "AArch64 pointers are 64-bit");
_Static_assert(sizeof(long double) == 8, "Windows ARM64 long double is binary64");

int
newlib_probe(void)
{
  return (int) sizeof(uintptr_t) + (int) sizeof(FILE *);
}
