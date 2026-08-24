#include <atomic>
#include <cstddef>
#include <cstdlib>
#include <cstdint>
#include <ctime>
#include <cwchar>
#include <new>
#include <thread>
#include <type_traits>

#ifndef _GLIBCXX_HAS_GTHREADS
#error MSYS target headers must enable gthreads
#endif

#ifndef _GLIBCXX_USE_WCHAR_T
#error MSYS target headers must enable wchar_t support
#endif

#ifndef __GTHREADS_CXX0X
#error MSYS target headers must expose the C++11 gthread interface
#endif

static_assert(sizeof(long) == 8);
static_assert(sizeof(void *) == 8);
static_assert(sizeof(std::size_t) == 8);
static_assert(sizeof(wchar_t) == 2);
static_assert(std::atomic<std::uint64_t>::is_always_lock_free);
static_assert(std::is_same_v<std::remove_cv_t<const int>, int>);

struct alignas(64) over_aligned
{
  std::uint64_t value;
};

int *
placement_construct(void *storage)
{
  return ::new (storage) int(42);
}

void
placement_deallocate(void *pointer, void *storage)
{
  ::operator delete(pointer, storage);
}

void *
aligned_allocate(std::size_t size)
{
  return ::operator new(size, std::align_val_t{64});
}

void
sized_deallocate(void *pointer, std::size_t size)
{
  ::operator delete(pointer, size);
}

void
aligned_sized_deallocate(void *pointer, std::size_t size)
{
  ::operator delete(pointer, size, std::align_val_t{64});
}

std::size_t
wide_length(const wchar_t *text)
{
  return std::wcslen(text);
}

std::thread *
thread_declaration_only(std::thread *thread)
{
  return thread;
}

void *
cxx17_aligned_allocate(std::size_t size)
{
  return std::aligned_alloc(64, size);
}

int
cxx17_timespec_get(std::timespec *time)
{
  return std::timespec_get(time, TIME_UTC);
}

auto cxx11_at_quick_exit = &std::at_quick_exit;
auto cxx11_quick_exit = &std::quick_exit;
