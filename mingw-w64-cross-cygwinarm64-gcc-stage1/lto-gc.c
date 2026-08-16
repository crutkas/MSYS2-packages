volatile __int128 lto_result;
volatile __int128 lto_dividend;
volatile __int128 lto_divisor;

__attribute__((noinline))
static __int128
divide_128(__int128 dividend, __int128 divisor)
{
  return dividend / divisor;
}

__attribute__((noinline))
int
discarded_by_gc(void)
{
  return 0x55aa;
}

void
lto_gc_entry(void)
{
  lto_result = divide_128(lto_dividend, lto_divisor);
}
