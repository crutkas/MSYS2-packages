__thread unsigned long cygtls_slot;

unsigned long *
tls_address(void)
{
  return &cygtls_slot;
}
