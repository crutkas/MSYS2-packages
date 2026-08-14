unsigned long
register_pressure(unsigned long seed)
{
  volatile unsigned long values[24];
  unsigned int index;
  unsigned long result = seed;

  for (index = 0; index < 24; ++index)
    values[index] = seed + index * 17;
  for (index = 0; index < 24; ++index)
    result = (result << 3) ^ values[index];
  return result;
}
