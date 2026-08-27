#include <sqlite3.h>
#include <stdio.h>
#include <string.h>

static int execute(sqlite3 *db, const char *sql)
{
  char *error = NULL;
  int result = sqlite3_exec(db, sql, NULL, NULL, &error);

  if (result != SQLITE_OK) {
    fprintf(stderr, "%s\n", error == NULL ? "sqlite3_exec failed" : error);
    sqlite3_free(error);
  }
  return result;
}

int main(void)
{
  sqlite3 *db = NULL;
  sqlite3_stmt *statement = NULL;
  int value = 0;
  int result = sqlite3_open(":memory:", &db);

  if (result != SQLITE_OK)
    goto done;
  if (sqlite3_version[0] == '\0' ||
      strcmp(sqlite3_version, sqlite3_libversion()) != 0) {
    result = SQLITE_ERROR;
    goto done;
  }
  result = execute(db,
                   "BEGIN IMMEDIATE;"
                   "CREATE TABLE values_to_sum(value INTEGER NOT NULL);"
                   "INSERT INTO values_to_sum VALUES (19), (23);"
                   "COMMIT;");
  if (result != SQLITE_OK)
    goto done;
  result = execute(db,
                   "BEGIN;"
                   "INSERT INTO values_to_sum VALUES (1000);"
                   "ROLLBACK;");
  if (result != SQLITE_OK)
    goto done;
  result = sqlite3_prepare_v2(
      db, "SELECT sum(value) FROM values_to_sum", -1, &statement, NULL);
  if (result != SQLITE_OK)
    goto done;
  result = sqlite3_step(statement);
  if (result != SQLITE_ROW)
    goto done;
  value = sqlite3_column_int(statement, 0);
  result = value == 42 ? SQLITE_OK : SQLITE_ERROR;

done:
  sqlite3_finalize(statement);
  sqlite3_close(db);
  return result == SQLITE_OK ? 0 : 1;
}
