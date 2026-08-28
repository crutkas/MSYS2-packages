/*
 * npth-dynamic-smoke.c -- dynamic (shared) npth consumer.
 *
 * Linked against the import library libnpth.dll.a, so the produced AArch64 MSYS
 * executable imports msys-npth-<soname>.dll and must resolve it at run time on a
 * genuine windows-11-arm host. Exercises the real npth entry points and prints
 * explicit success/failure markers the native admission job asserts on.
 */
#include <npth.h>
#include <stdio.h>
#include <string.h>

_Static_assert (sizeof (long) == 8, "aarch64-pc-msys must use LP64");
_Static_assert (sizeof (void *) == 8, "aarch64-pc-msys pointers must be 64-bit");

static void *
worker (void *arg)
{
  int *value = (int *) arg;
  *value = 42;
  return value;
}

int
main (void)
{
  npth_t thread;
  void *result = NULL;
  int payload = 0;
  int rc;

  if (sizeof (long) != 8 || sizeof (void *) != 8)
    {
      fputs ("NPTH-DYNAMIC-FAIL data-model\n", stderr);
      return 3;
    }

  if (npth_init ())
    {
      fputs ("NPTH-DYNAMIC-FAIL npth_init\n", stderr);
      return 1;
    }

  rc = npth_create (&thread, NULL, worker, &payload);
  if (rc)
    {
      fprintf (stderr, "NPTH-DYNAMIC-FAIL npth_create=%d\n", rc);
      return 2;
    }

  rc = npth_join (thread, &result);
  if (rc || result != &payload || payload != 42)
    {
      fprintf (stderr, "NPTH-DYNAMIC-FAIL npth_join=%d payload=%d\n", rc, payload);
      return 4;
    }

  puts ("NPTH-DYNAMIC-READY");
  fflush (stdout);
  npth_sleep (3);
  puts ("NPTH-DYNAMIC-OK");
  return 0;
}
