#include <stdio.h>
#include <string.h>
#include <uuid/uuid.h>

int
main(void)
{
  char text[37];
  uuid_t generated;
  uuid_t parsed;

  uuid_generate(generated);
  uuid_unparse_lower(generated, text);
  if (strlen(text) != 36 || uuid_parse(text, parsed) != 0)
    return 1;
  if (uuid_compare(generated, parsed) != 0 || uuid_is_null(parsed))
    return 2;

  printf("libuuid-smoke:%s\n", text);
  return 0;
}
