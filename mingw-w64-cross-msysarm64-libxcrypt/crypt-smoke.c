#include <crypt.h>
#include <stdio.h>
#include <string.h>

int
main(void)
{
  static const char password[] = "password";
  static const char salt[] = "ab";
  static const char expected[] = "abJnggxhB/yWI";
  char *hash = crypt(password, salt);

  if (hash == NULL) {
    fputs("crypt returned NULL\n", stderr);
    return 1;
  }
  if (strcmp(hash, expected) != 0) {
    fprintf(stderr, "unexpected crypt result: %s\n", hash);
    return 2;
  }

  printf("aarch64-pc-msys libxcrypt smoke: %s\n", hash);
  return 0;
}
