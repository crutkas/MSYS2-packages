struct per_thread_state
{
  void *stack_base;
  unsigned long thread_id;
};

extern "C" __attribute__((dllimport)) void SetLastError(unsigned long);
__thread per_thread_state cygtls_state;

extern "C" __attribute__((dllexport)) void
winsup_bootstrap(void *stack_base, unsigned long thread_id)
{
  cygtls_state.stack_base = stack_base;
  cygtls_state.thread_id = thread_id;
  SetLastError(0);
}
