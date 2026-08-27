#include <assuan.h>
#include <gpg-error.h>
#include <stdio.h>
#include <string.h>

_Static_assert (sizeof (long) == 8, "aarch64-pc-msys must use LP64");
_Static_assert (sizeof (void *) == 8, "aarch64-pc-msys pointers must be 64-bit");

int
main (void)
{
  assuan_context_t ctx = NULL;
  gpg_error_t err;
  const char *version;

  version = assuan_check_version (NULL);
  if (sizeof (long) != 8 || sizeof (void *) != 8)
    {
      fputs ("runtime data model is not LP64\n", stderr);
      return 3;
    }
  if (!version || strcmp (version, "3.0.2"))
    {
      fprintf (stderr, "unexpected libassuan version: %s\n",
               version ? version : "(null)");
      return 1;
    }

  err = assuan_new (&ctx);
  if (err)
    {
      fprintf (stderr, "assuan_new: %s\n", gpg_strerror (err));
      return 2;
    }

  assuan_release (ctx);
  puts ("libassuan context smoke passed");
  return 0;
}
