struct lifetime_probe
{
  lifetime_probe();
  ~lifetime_probe();
};

volatile int lifetime_state;

lifetime_probe::lifetime_probe()
{
  ++lifetime_state;
}

lifetime_probe::~lifetime_probe()
{
  --lifetime_state;
}

lifetime_probe global_lifetime_probe;
