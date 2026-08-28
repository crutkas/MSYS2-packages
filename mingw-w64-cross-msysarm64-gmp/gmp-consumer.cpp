#include <gmp.h>
#include <pthread.h>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <sys/wait.h>
#include <unistd.h>

#if !defined(__aarch64__) || !defined(__MSYS__) || !defined(_WIN64)
#error "This probe must target 64-bit ARM MSYS"
#endif

static_assert(sizeof(void *) == 8, "LP64 requires 64-bit pointers");
static_assert(sizeof(long) == 8, "MSYS ARM64 must use LP64");
static_assert(sizeof(mp_limb_t) == 8, "GMP limbs must be 64-bit");

static int destructor_count;

class CheckedInteger
{
public:
  CheckedInteger()
  {
    mpz_init_set_ui(value, 7);
  }

  ~CheckedInteger()
  {
    mpz_clear(value);
    ++destructor_count;
  }

  mpz_t value;
};

static int
check_exception_unwind()
{
  destructor_count = 0;
  try
    {
      CheckedInteger number;
      mpz_mul_ui(number.value, number.value, 6);
      if (mpz_cmp_ui(number.value, 42) != 0)
        return 1;
      throw 42;
    }
  catch (int value)
    {
      return value == 42 && destructor_count == 1 ? 0 : 2;
    }
}

static int
check_product()
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

  mpz_inits(a, b, product, nullptr);
  result = mpz_set_str(a, left, 10) != 0 || mpz_set_str(b, right, 10) != 0;
  if (!result)
    {
      mpz_mul(product, a, b);
      actual = mpz_get_str(nullptr, 10, product);
      result = actual == nullptr || std::strcmp(actual, expected) != 0;
      std::free(actual);
    }
  mpz_clears(a, b, product, nullptr);
  return result;
}

static void *
thread_main(void *)
{
  return reinterpret_cast<void *>(static_cast<intptr_t>(check_product()));
}

int
main(int argc, char **argv)
{
  pthread_t thread;
  void *thread_result = nullptr;
  pid_t child;
  int status;

  if (check_product() != 0)
    return 10;
  if (check_exception_unwind() != 0)
    return 11;
  if (argc == 2 && std::strcmp(argv[1], "--child") == 0)
    return 0;
  if (pthread_create(&thread, nullptr, thread_main, nullptr) != 0)
    return 20;
  if (pthread_join(thread, &thread_result) != 0 || thread_result != nullptr)
    return 21;

  child = fork();
  if (child < 0)
    return 30;
  if (child == 0)
    _exit(check_product() == 0 ? 0 : 31);
  if (waitpid(child, &status, 0) != child || !WIFEXITED(status)
      || WEXITSTATUS(status) != 0)
    return 32;

  if (std::getenv("GMP_MODULE_HOLD") != nullptr)
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
