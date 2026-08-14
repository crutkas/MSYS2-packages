typedef __PTRDIFF_TYPE__ ptrdiff_t;

struct _reent
{
  int _errno;
};

extern char __heap_start[];
static char *heap_end;

void *
_sbrk_r(struct _reent *reent, ptrdiff_t increment)
{
  char *previous;

  if (heap_end == 0)
    heap_end = __heap_start;
  previous = heap_end;
  heap_end += increment;
  reent->_errno = 0;
  return previous;
}
