typedef __builtin_va_list compiler_va_list;

_Static_assert(sizeof(long) == 8, "Cygwin AArch64 long must be 8 bytes");
_Static_assert(sizeof(void *) == 8, "Cygwin AArch64 pointers must be 8 bytes");
_Static_assert(sizeof(long double) == 8,
               "Cygwin AArch64 long double must be 8 bytes");
_Static_assert(sizeof(compiler_va_list) == 32,
               "Cygwin AArch64 va_list must use the AAPCS64 layout");
_Static_assert(_Alignof(compiler_va_list) == 8,
               "Cygwin AArch64 va_list alignment must be 8 bytes");

long
abi_probe(compiler_va_list *args, long value)
{
  return value + (long) sizeof(*args);
}
