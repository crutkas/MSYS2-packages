extern void consume_frame(const void *);

__attribute__((noinline)) int
seh_frame(int value)
{
  volatile unsigned char frame[96];

  frame[0] = (unsigned char) value;
  frame[95] = (unsigned char) (value >> 1);
  consume_frame((const void *) frame);
  return frame[0] + frame[95];
}
