#include <atomic>
#include <cstdint>

std::atomic<std::uint64_t> atomic_value{0};
std::atomic<void *> atomic_pointer{nullptr};

std::uint64_t
atomic_increment()
{
  return atomic_value.fetch_add(1, std::memory_order_acq_rel);
}

void *
atomic_exchange(void *value)
{
  return atomic_pointer.exchange(value, std::memory_order_acq_rel);
}
