#include <gcrypt.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

int
main(void)
{
  static const unsigned char expected[32] = {
    0xba, 0x78, 0x16, 0xbf, 0x8f, 0x01, 0xcf, 0xea,
    0x41, 0x41, 0x40, 0xde, 0x5d, 0xae, 0x22, 0x23,
    0xb0, 0x03, 0x61, 0xa3, 0x96, 0x17, 0x7a, 0x9c,
    0xb4, 0x10, 0xff, 0x61, 0xf2, 0x00, 0x15, 0xad
  };
  unsigned char digest[32];
  const char *version = gcry_check_version(GCRYPT_VERSION);

  if (!version)
    return 2;

  if (gcry_control(GCRYCTL_SELFTEST, 0) != 0)
    return 3;

  gcry_md_hash_buffer(GCRY_MD_SHA256, digest, "abc", 3);
  if (memcmp(digest, expected, sizeof(expected)) != 0)
    return 4;

  printf("libgcrypt=%s api=%s selftest=ok sha256=ok\n", version, GCRYPT_VERSION);
  fflush(stdout);
  if (getenv("LIBGCRYPT_NATIVE_HOLD"))
    sleep(15);
  return 0;
}
