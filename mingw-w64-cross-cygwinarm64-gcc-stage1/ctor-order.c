volatile int ctor_order_state;

void
user_ctor(void)
{
  ctor_order_state |= 1;
}

void
user_dtor(void)
{
  ctor_order_state |= 2;
}

static void user_ctor_entry(void) __attribute__((constructor));
static void user_dtor_entry(void) __attribute__((destructor));

static void
user_ctor_entry(void)
{
  user_ctor();
}

static void
user_dtor_entry(void)
{
  user_dtor();
}
