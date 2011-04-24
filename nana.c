#include<stdio.h>
#include<stdlib.h>
#include<string.h>
#include<unistd.h>
#include<errno.h>
#include<regex.h>
#include<netdb.h>
#include<signal.h>
#include<sys/socket.h>
#include<sys/types.h>
#include<sys/wait.h>
#include<sys/time.h>
#include<sys/unistd.h>
#include<sys/select.h>
#include<netinet/in.h>
#include<arpa/inet.h>

#include <libdaemon/dfork.h>
#include <libdaemon/dsignal.h>
#include <libdaemon/dlog.h>
#include <libdaemon/dpid.h>
#include <libdaemon/dexec.h>

// The nana daemon runs on port 80
#define LOCAL_PORT 80

// First target is apache running on localhost:8088
#define TARGET1_REGEX "HTTP"
#define TARGET1_HOST "localhost"
#define TARGET1_PORT 8088
#define TARGET1_SERVER_FIRST 0 // In HTTP, client talks first.

// Second target is vncserver running on localhost:5901
#define TARGET2_REGEX "RFB"
#define TARGET2_HOST "localhost"
#define TARGET2_PORT 5901
#define TARGET2_SERVER_FIRST 1 // In VNC, server talks first.

#define BUFSIZE 4096

void loop(const int in_socket, const int out_socket)
{
  fd_set iofds, c_iofds;
  int max_fd;
  unsigned long bytes;
  char buf[BUFSIZE];

  FD_ZERO(&iofds);
  FD_SET(in_socket, &iofds);
  FD_SET(out_socket, &iofds);

  if (in_socket > out_socket){
    max_fd = in_socket;
  } else {
    max_fd = out_socket;
  }

  while(1){
    (void) memcpy(&c_iofds, &iofds, sizeof(iofds));

    if (select(max_fd+1, &c_iofds, (fd_set *)0, (fd_set *)0, NULL) <= 0){
      break;
    }

    if(FD_ISSET(in_socket, &c_iofds)){
      if((bytes = read(in_socket, buf, sizeof(buf))) <= 0){
	break;
      }
      if(write(out_socket, buf, bytes) != bytes){
	break;
      }
    }
    if(FD_ISSET(out_socket, &c_iofds)){
      if((bytes = read(out_socket, buf, sizeof(buf))) <= 0){
	break;
      }
      if(write(in_socket, buf, bytes) != bytes){
	break;
      }
    }
  }

  shutdown(in_socket,0);
  shutdown(out_socket,0);
  close(in_socket);
  close(out_socket);
  return;
}

void do_accept(const int server_socket)
{
  int client_socket, target_socket;
  struct sockaddr_in client, target;
  unsigned int client_len = sizeof(client);
  unsigned long bytes;
  char buf[BUFSIZE];
  regex_t pat;
  regmatch_t match;
  struct hostent *hp;
  char *client_ip;
  int protocol_matched = 0;
  int read_from_server_first = 0;

  if ((client_socket = accept(server_socket, (struct sockaddr *)&client,
			   &client_len)) < 0){
    daemon_log(LOG_ERR, "server: accept");
    switch(errno) {
    case EHOSTUNREACH:
    case ECONNRESET:
    case ETIMEDOUT:
      return;
    default:
      exit(1);
    }
  }

  /*
   * Double fork here so we don't have to wait later
   * This detaches us from our parent so that the parent
   * does not need to pick up dead kids later.
   *
   * This needs to be done before the hosts_access stuff, because
   * extended hosts_access options expect to be run from a child.
   */
  switch(fork()){
  case -1: /* Error */
    daemon_log(LOG_ERR, "(server) fork");
    _exit(1);
  case 0:  /* Child */
    break;
  default: /* Parent */
    {
      int status;
	  
      /* Wait for child (who has forked off grandchild) */
      (void) wait(&status);

      /* Close sockets to prevent confusion */
      close(client_socket);
	
      return;
    }
  }

  /* We are now the first child. Fork again and exit */
	  
  switch(fork())
    {
    case -1: /* Error */
      daemon_log(LOG_ERR, "(client) fork");
      _exit(1);
    case 0:  /* Child */
      break;
    default: /* Parent */
      _exit(0);
    }

  /* We are now the grandchild */

  client_ip = strdup(inet_ntoa(client.sin_addr));
  daemon_log(LOG_INFO, "Connection from %s", client_ip);

  bytes = read(client_socket, buf, sizeof(buf));

  if ((target_socket = socket(AF_INET, SOCK_STREAM, 0)) < 0){
    daemon_log(LOG_ERR, "target: socket");
    _exit(1);
  }

  target.sin_family = AF_INET;

  regcomp(&pat, TARGET1_REGEX, REG_EXTENDED);
  if (0 == regexec(&pat, buf, 1, &match, 0)){
    hp = gethostbyname(TARGET1_HOST);
    memcpy(&target.sin_addr, hp->h_addr, hp->h_length);
    target.sin_port = htons(TARGET1_PORT);
    read_from_server_first = TARGET1_SERVER_FIRST;
    protocol_matched = 1;
  }
  regfree(&pat);

  regcomp(&pat, TARGET2_REGEX, REG_EXTENDED);
  if (0 == regexec(&pat, buf, 1, &match, 0)){
    hp = gethostbyname(TARGET2_HOST);
    memcpy(&target.sin_addr, hp->h_addr, hp->h_length);
    target.sin_port = htons(TARGET2_PORT);
    read_from_server_first = TARGET2_SERVER_FIRST;
    protocol_matched = 1;
  }
  regfree(&pat);

  if (!protocol_matched){
    daemon_log(LOG_ERR, "target: unknown protocol");
    _exit(1);
  }

  if (connect(target_socket, (struct sockaddr *)&target, 
	      sizeof(struct sockaddr_in)) < 0){
    daemon_log(LOG_ERR, "target: connect");
    _exit(1);
  }

  if (read_from_server_first){
    read(target_socket, buf, bytes); // read and discard.
  }

  write(target_socket, buf, bytes);

  loop(client_socket, target_socket);
  exit(0);
}

int create_server_socket(const int port)
{
  int server_socket;
  struct sockaddr_in server;

  if ((server_socket = socket(AF_INET, SOCK_STREAM, 0)) < 0){
    perror("server: socket");
    exit(1);
  }

  memset(&server, 0, sizeof(server));
  server.sin_family = AF_INET;
  server.sin_port = htons(port);
  server.sin_addr.s_addr = htonl(inet_addr("0.0.0.0"));
     
  if (bind(server_socket, (struct sockaddr *)&server, sizeof(server)) < 0){
    daemon_log(LOG_ERR, "server: bind");
    exit(1);
  }
     
  if (listen(server_socket, 10) < 0){
    daemon_log(LOG_ERR, "server: listen");
    exit(1);
  }
     
  return server_socket;
}

int main(int argc, char *argv[])
{
  pid_t pid;
  int server_socket;

  /* Reset signal handlers */
  if (daemon_reset_sigs(-1) < 0) {
    daemon_log(LOG_ERR, "Failed to reset all signal handlers: %s", strerror(errno));
    return 1;
  }

  /* Unblock signals */
  if (daemon_unblock_sigs(-1) < 0) {
    daemon_log(LOG_ERR, "Failed to unblock all signals: %s", strerror(errno));
    return 1;
  }

  /* Set indetification string for the daemon for both syslog and PID file */
  daemon_pid_file_ident = daemon_log_ident = daemon_ident_from_argv0(argv[0]);

  /* Check if we are called with -k parameter */
  if (argc >= 2 && !strcmp(argv[1], "-k")) {
    int ret;

    /* Kill daemon with SIGTERM */

    /* Check if the new function daemon_pid_file_kill_wait() is available, if it is, use it. */
    if ((ret = daemon_pid_file_kill_wait(SIGTERM, 5)) < 0)
      daemon_log(LOG_WARNING, "Failed to kill daemon: %s", strerror(errno));

    return ret < 0 ? 1 : 0;
  }

  /* Check that the daemon is not rung twice a the same time */
  if ((pid = daemon_pid_file_is_running()) >= 0) {
    daemon_log(LOG_ERR, "Daemon already running on PID file %u", pid);
    return 1;
  }

  /* Prepare for return value passing from the initialization procedure of the daemon process */
  if (daemon_retval_init() < 0) {
    daemon_log(LOG_ERR, "Failed to create pipe.");
    return 1;
  }

  /* Do the fork */
  if ((pid = daemon_fork()) < 0) {

    /* Exit on error */
    daemon_retval_done();
    return 1;

  } else if (pid) { /* The parent */
    int ret;

    /* Wait for 20 seconds for the return value passed from the daemon process */
    if ((ret = daemon_retval_wait(20)) < 0) {
      daemon_log(LOG_ERR, "Could not recieve return value from daemon process: %s", strerror(errno));
      return 255;
    }

    //daemon_log(ret != 0 ? LOG_ERR : LOG_INFO, "Daemon returned %i as return value.", ret);
    if (ret != 0){
      daemon_log(LOG_ERR, "Daemon returned %i as return value.", ret);
    }
    return ret;
  } else { /* The daemon */
    int fd, quit = 0;
    fd_set fds;

    /* Close FDs */
    if (daemon_close_all(-1) < 0) {
      daemon_log(LOG_ERR, "Failed to close all file descriptors: %s", strerror(errno));

      /* Send the error condition to the parent process */
      daemon_retval_send(1);
      goto finish;
    }

    /* Create the PID file */
    if (daemon_pid_file_create() < 0) {
      daemon_log(LOG_ERR, "Could not create PID file (%s).", strerror(errno));
      daemon_retval_send(2);
      goto finish;
    }

    /* Initialize signal handling */
    if (daemon_signal_init(SIGINT, SIGTERM, SIGQUIT, SIGHUP, 0) < 0) {
      daemon_log(LOG_ERR, "Could not register signal handlers (%s).", strerror(errno));
      daemon_retval_send(3);
      goto finish;
    }

    /*... do some further init work here */

    /* Send OK to parent process */
    daemon_retval_send(0);

    daemon_log(LOG_INFO, "Sucessfully started");

    /* Prepare for select() on the signal fd */
    FD_ZERO(&fds);
    fd = daemon_signal_fd();
    FD_SET(fd, &fds);

    server_socket = create_server_socket(LOCAL_PORT);
    FD_SET(server_socket, &fds);

    while (!quit) {
      fd_set fds2 = fds;

      /* Wait for an incoming signal */
      if (select(FD_SETSIZE, &fds2, 0, 0, 0) < 0) {

	/* If we've been interrupted by an incoming signal, continue */
	if (errno == EINTR)
	  continue;

	daemon_log(LOG_ERR, "select(): %s", strerror(errno));
	break;
      }

      if (FD_ISSET(server_socket, &fds2)){
	do_accept(server_socket);
      }

      /* Check if a signal has been recieved */
      if (FD_ISSET(fd, &fds2)) {
	int sig;

	/* Get signal */
	if ((sig = daemon_signal_next()) <= 0) {
	  daemon_log(LOG_ERR, "daemon_signal_next() failed: %s", strerror(errno));
	  break;
	}

	/* Dispatch signal */
	switch (sig) {

	case SIGINT:
	case SIGQUIT:
	case SIGTERM:
	  daemon_log(LOG_WARNING, "Got SIGINT, SIGQUIT or SIGTERM.");
	  quit = 1;
	  break;

	case SIGHUP:
	  daemon_log(LOG_INFO, "Got a HUP");
	  //daemon_exec("/", NULL, "/bin/ls", "ls", (char*) NULL);
	  break;

	}
      }
    }
    
    /* Do a cleanup */
  finish:
    daemon_log(LOG_INFO, "Exiting...");
    daemon_retval_send(255);
    daemon_signal_done();
    daemon_pid_file_remove();

    return 0;
  }
}
