#include <gmp.h>
#include <pthread.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>
#include <unistd.h>

#if !defined(__aarch64__) || !defined(__MSYS__) || !defined(_WIN64)
#error "This probe must target 64-bit ARM MSYS"
#endif

_Static_assert(sizeof(void *) == 8, "LP64 requires 64-bit pointers");
_Static_assert(sizeof(long) == 8, "MSYS ARM64 must use LP64");
_Static_assert(sizeof(mp_limb_t) == 8, "GMP limbs must be 64-bit");

static int
check_product(void)
{
  static const char left[] = "123456789012345678901234567890123456789";
  static const char right[] = "98765432109876543210987654321";
  static const char expected[] =
    "12193263113702179522618503273374485596336229233322374638011112635269";
  char *actual;
  int result;
  mpz_t a;
  mpz_t b;
  mpz_t product;

  mpz_inits(a, b, product, NULL);
  result = mpz_set_str(a, left, 10) != 0 || mpz_set_str(b, right, 10) != 0;
  if (!result)
    {
      mpz_mul(product, a, b);
      actual = mpz_get_str(NULL, 10, product);
      result = actual == NULL || strcmp(actual, expected) != 0;
      free(actual);
    }
  mpz_clears(a, b, product, NULL);
  return result;
}

static void *
thread_main(void *unused)
{
  (void) unused;
  return (void *) (intptr_t) check_product();
}

int
main(int argc, char **argv)
{
  pthread_t thread;
  void *thread_result = NULL;
  pid_t child;
  int status;

  if (check_product() != 0)
    return 10;
  if (argc == 2 && strcmp(argv[1], "--child") == 0)
    return 0;
  if (pthread_create(&thread, NULL, thread_main, NULL) != 0)
    return 20;
  if (pthread_join(thread, &thread_result) != 0 || thread_result != NULL)
    return 21;

  child = fork();
  if (child < 0)
    return 30;
  if (child == 0)
    _exit(check_product() == 0 ? 0 : 31);
  if (waitpid(child, &status, 0) != child || !WIFEXITED(status)
      || WEXITSTATUS(status) != 0)
    return 32;

  if (getenv("GMP_MODULE_HOLD") != NULL)
    {
      static const char ready[] = "gmp-module-ready\n";
      if (write(STDOUT_FILENO, ready, sizeof(ready) - 1) < 0)
        return 40;
      sleep(60);
    }
  static const char result[] =
    "gmp-smoke-ok abi=LP64 call=AAPCS64 unwind=SEH thread=ok process=ok\n";
  if (write(STDOUT_FILENO, result, sizeof(result) - 1) < 0)
    return 41;
  return 0;
}
