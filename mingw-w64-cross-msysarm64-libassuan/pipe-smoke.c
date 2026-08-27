#include <assuan.h>
#include <gpg-error.h>
#include <stdio.h>
#include <string.h>

static gpg_error_t
cmd_ping (assuan_context_t ctx, char *line)
{
  (void)ctx;
  (void)line;
  return 0;
}

static int
run_server (void)
{
  assuan_context_t ctx = NULL;
  assuan_fd_t filedes[2];
  gpg_error_t err;

  filedes[0] = assuan_fd_from_posix_fd (0);
  filedes[1] = assuan_fd_from_posix_fd (1);

  err = assuan_new (&ctx);
  if (!err)
    err = assuan_init_pipe_server (ctx, filedes);
  if (!err)
    err = assuan_register_command (ctx, "PING", cmd_ping, NULL);
  if (!err)
    err = assuan_accept (ctx);
  if (!err)
    err = assuan_process (ctx);

  assuan_release (ctx);
  if (err && gpg_err_code (err) != GPG_ERR_EOF)
    {
      fprintf (stderr, "server: %s\n", gpg_strerror (err));
      return 10;
    }
  return 0;
}

static int
run_client (const char *self)
{
  assuan_context_t ctx = NULL;
  assuan_fd_t no_close[2];
  const char *argv[3];
  gpg_error_t err;
  int status = 0;

  no_close[0] = assuan_fd_from_posix_fd (2);
  no_close[1] = ASSUAN_INVALID_FD;
  argv[0] = self;
  argv[1] = "--server";
  argv[2] = NULL;

  err = assuan_new (&ctx);
  if (!err)
    err = assuan_pipe_connect (ctx, self, argv, no_close, NULL, NULL, 0);
  if (!err)
    err = assuan_transact (ctx, "PING", NULL, NULL, NULL, NULL, NULL, NULL);
  if (!err)
    err = assuan_transact (ctx, "BYE", NULL, NULL, NULL, NULL, NULL, NULL);
  if (!err)
    err = assuan_pipe_wait_server_termination (ctx, &status, 0);

  assuan_release (ctx);
  if (err)
    {
      fprintf (stderr, "client: %s\n", gpg_strerror (err));
      return 20;
    }
  if (status)
    {
      fprintf (stderr, "server exit status: %d\n", status);
      return 21;
    }

  puts ("libassuan pipe smoke passed");
  return 0;
}

int
main (int argc, char **argv)
{
  gpg_error_t err;

  err = assuan_sock_init ();
  if (err)
    {
      fprintf (stderr, "assuan_sock_init: %s\n", gpg_strerror (err));
      return 1;
    }

  if (argc == 2 && !strcmp (argv[1], "--server"))
    return run_server ();
  if (argc != 1)
    return 2;
  return run_client (argv[0]);
}
