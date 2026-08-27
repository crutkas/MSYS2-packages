#include <assuan.h>
#include <gpg-error.h>
#include <pthread.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

struct server_state
{
  int request_fd;
  int response_fd;
  gpg_error_t err;
  int ping_seen;
};

static gpg_error_t
cmd_ping (assuan_context_t ctx, char *line)
{
  struct server_state *state = assuan_get_pointer (ctx);

  (void)line;
  state->ping_seen = 1;
  return 0;
}

static void *
run_server (void *opaque)
{
  struct server_state *state = opaque;
  assuan_context_t ctx = NULL;
  assuan_fd_t filedes[2];
  gpg_error_t err;

  filedes[0] = assuan_fd_from_posix_fd (state->request_fd);
  filedes[1] = assuan_fd_from_posix_fd (state->response_fd);

  err = assuan_new (&ctx);
  if (!err)
    {
      assuan_set_pointer (ctx, state);
      err = assuan_init_pipe_server (ctx, filedes);
    }
  if (!err)
    err = assuan_register_command (ctx, "PING", cmd_ping, NULL);
  if (!err)
    err = assuan_accept (ctx);
  if (!err)
    err = assuan_process (ctx);
  if (err && gpg_err_code (err) == GPG_ERR_EOF)
    err = 0;

  assuan_release (ctx);
  state->err = err;
  return NULL;
}

static int
write_all (int fd, const char *buffer, size_t length)
{
  while (length)
    {
      ssize_t written = write (fd, buffer, length);

      if (written <= 0)
        return -1;
      buffer += written;
      length -= (size_t)written;
    }
  return 0;
}

int
main (void)
{
  static const char request[] = "PING\nBYE\n";
  struct server_state state = { -1, -1, 0, 0 };
  pthread_t thread;
  char response[1024];
  size_t used = 0;
  gpg_error_t err;
  int requests[2];
  int responses[2];

  err = assuan_sock_init ();
  if (err)
    {
      fprintf (stderr, "assuan_sock_init failed: %u\n", (unsigned int)err);
      return 1;
    }
  if (pipe (requests) || pipe (responses))
    {
      fputs ("pipe creation failed\n", stderr);
      return 2;
    }

  state.request_fd = requests[0];
  state.response_fd = responses[1];
  if (pthread_create (&thread, NULL, run_server, &state))
    {
      fputs ("server thread creation failed\n", stderr);
      return 3;
    }
  if (write_all (requests[1], request, sizeof request - 1))
    {
      fputs ("protocol request write failed\n", stderr);
      return 4;
    }
  close (requests[1]);

  while (used + 1 < sizeof response)
    {
      ssize_t count = read (responses[0], response + used,
                            sizeof response - used - 1);

      if (count < 0)
        {
          fputs ("protocol response read failed\n", stderr);
          return 6;
        }
      if (!count)
        break;
      used += (size_t)count;
    }
  close (responses[0]);
  response[used] = '\0';

  if (pthread_join (thread, NULL))
    {
      fputs ("server thread join failed\n", stderr);
      return 5;
    }
  if (state.err)
    {
      fprintf (stderr, "server failed: %u\n", (unsigned int)state.err);
      return 10;
    }
  if (!state.ping_seen || !strstr (response, "OK"))
    {
      fprintf (stderr, "invalid Assuan response: %s\n", response);
      return 20;
    }

  puts ("libassuan pipe server smoke passed");
  return 0;
}
