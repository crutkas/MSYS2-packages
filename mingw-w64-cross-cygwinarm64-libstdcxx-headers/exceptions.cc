#include <type_traits>

struct exception_probe
{
  int value;
};

static_assert(std::is_trivially_copyable_v<exception_probe>);

int
throw_and_catch(bool enabled)
{
  try
    {
      if (enabled)
        throw exception_probe{42};
    }
  catch (const exception_probe &value)
    {
      return value.value;
    }
  return 0;
}
