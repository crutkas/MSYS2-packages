/*
 * npth-static-smoke.c -- static npth consumer.
 *
 * Linked directly against libnpth.a, so the produced AArch64 MSYS executable
 * carries no npth DLL import and must run purely on msys-2.0.dll on a genuine
 * windows-11-arm host. Exercises the real npth entry points and prints explicit
 * success/failure markers the native admission job asserts on.
 */
#include <npth.h>
#include <stdio.h>
#include <string.h>

_Static_assert (sizeof (long) == 8, "aarch64-pc-msys must use LP64");
_Static_assert (sizeof (void *) == 8, "aarch64-pc-msys pointers must be 64-bit");

int
main (void)
{
  npth_mutex_t mutex;
  int rc;

  if (sizeof (long) != 8 || sizeof (void *) != 8)
    {
      fputs ("NPTH-STATIC-FAIL data-model\n", stderr);
      return 3;
    }

  if (npth_init ())
    {
      fputs ("NPTH-STATIC-FAIL npth_init\n", stderr);
      return 1;
    }

  rc = npth_mutex_init (&mutex, NULL);
  if (rc)
    {
      fprintf (stderr, "NPTH-STATIC-FAIL npth_mutex_init=%d\n", rc);
      return 2;
    }

  rc = npth_mutex_lock (&mutex);
  if (rc)
    {
      fprintf (stderr, "NPTH-STATIC-FAIL npth_mutex_lock=%d\n", rc);
      return 4;
    }

  rc = npth_mutex_unlock (&mutex);
  if (rc)
    {
      fprintf (stderr, "NPTH-STATIC-FAIL npth_mutex_unlock=%d\n", rc);
      return 5;
    }

  rc = npth_mutex_destroy (&mutex);
  if (rc)
    {
      fprintf (stderr, "NPTH-STATIC-FAIL npth_mutex_destroy=%d\n", rc);
      return 6;
    }

  puts ("NPTH-STATIC-OK");
  return 0;
}
