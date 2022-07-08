/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/** @file
 * @brief Library _init() tests
 *
 * Library for _init() function tests
 *
 * @author Nikita Rastegaev <Nikita.Rastegaev@oktetlabs.ru>
 *
 * $Id$
 */

#include <sys/wait.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include <errno.h>
#include <pthread.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#ifndef UNUSED
#define UNUSED(_x)      (void)(_x)
#endif

#define LT_LIBRARY_NAME     "init_test"
#define LT_TEST_STR         "String_for_testing"
#define LT_MAX_SEQ_LEN      256
#define LT_TIMING_DELAY     1

#define CHECK_RC(expr_) \
    do {                                                                \
        if ((expr_) < 0)                                                \
        {                                                               \
            perror(#expr_);                                             \
            exit(EXIT_FAILURE);                                         \
        }                                                               \
    } while (0)

#define SOCKET_CLOSE(_sock) \
    do {                                \
        if (_sock >= 0)                 \
            CHECK_RC(close(_sock));     \
    } while(0)

#define GENERATE_CONNECTION(_sock, _type, _recv) \
    do {                                                                \
        struct sockaddr_in  addr;                                       \
        int                 lsock;                                      \
                                                                        \
        CHECK_RC((lsock) = socket(AF_INET, _type, 0));                  \
                                                                        \
        memset(&addr, 0, sizeof(addr));                                 \
        addr.sin_family = AF_INET;                                      \
        CHECK_RC(inet_pton(AF_INET, getenv("LIBINIT_ADDR"),             \
                           &addr.sin_addr));                            \
        addr.sin_port = htons(atoi(getenv("LIBINIT_PORT")));            \
                                                                        \
        if (!(_recv))                                                   \
        {                                                               \
            CHECK_RC(connect(lsock, (struct sockaddr *)&addr,           \
                             sizeof(addr)));                            \
            _sock = lsock;                                              \
        }                                                               \
        else                                                            \
        {                                                               \
            CHECK_RC(bind(lsock, (struct sockaddr *)&addr,              \
                          sizeof(addr)));                               \
            if (_type == SOCK_STREAM)                                   \
            {                                                           \
                CHECK_RC(listen(lsock, 5));                             \
                CHECK_RC(_sock = accept(lsock, NULL, NULL));            \
                SOCKET_CLOSE(lsock);                                    \
            }                                                           \
            else                                                        \
                _sock = lsock;                                          \
        }                                                               \
    } while(0)
/* Mapping entry used to map iteration name to the set of flags */
struct map_entry
{
    const char *name;
    int         value;
};

/* Structure containing sequence and iteration names
 * obtained from TE through environment variables */
static struct lt_test_sequence
{
    char seq[LT_MAX_SEQ_LEN];
    int  iter;
} lt_ts;

/* Union containing global variables for different sequences.
 * For more information on each variable see corresponding
 * sequence's code */
static union lt_test_variables
{
    struct popen_vars {
        FILE    *fd;
    } popen;
    struct pipe_vars {
        int     pipefd[2];
    } pipe;
    struct fork_exec_vars {
        int     pipefd;
    } fork_exec;
    struct signal_vars {
        int     pipefd[2];
    } signal;
    struct signal_socket_vars {
        int     sock;
    } signal_socket;
    struct thread_fork_vars {
        pid_t   child;
        int     pipefd[2];
    } thread_fork;
    struct atfork_vars {
        int     sock;
    } atfork;
} lt_tv;

static int rc;

/* Test string used for sending and receiving on pipes and sockets.
 * Initially obtained from TE through environment variables */
static const char *test_str;
static int test_str_size;

/* Iteration mapping */
/* Each sequence has a map that pairs iteration name with
 * corresponding set of flags. For more information on different
 * iterations see @ref libinit-sequences_and_iterations */

/* hello */
#define HELLO_PRINT_POST        0x01
static struct map_entry hello_map[] =
{ { "PRINT_PRE_INIT", 0 },
  { "PRINT_POST_INIT", HELLO_PRINT_POST },
  { NULL, -1 } };

/* popen */
#define POPEN_READ_POST         0x01
static struct map_entry popen_map[] =
{ { "READ_PRE_INIT", 0 },
  { "READ_POST_INIT", POPEN_READ_POST },
  { NULL, -1} };

/* fork_exec */
#define FORKEXEC_READ_POST     0x01
static struct map_entry fork_exec_map[] =
{ { "READ_PRE_INIT", 0 },
  { "READ_POST_INIT", FORKEXEC_READ_POST },
  { NULL, -1} };

/* pipe */
#define PIPE_CHECK_POST         0x01
static struct map_entry pipe_map[] =
{ { "CHECK_PRE_INIT", 0 },
  { "CHECK_POST_INIT", PIPE_CHECK_POST },
  { NULL, -1 } };

/* signal */
#define SIGNAL_SIG_POST         0x01
#define SIGNAL_WRITE            0x02
#define SIGNAL_INT              0x04
static struct map_entry signal_map[] =
{ { "SIGNAL_USR1_PRE_INIT_READ", 0 },
  { "SIGNAL_USR1_POST_INIT_READ", SIGNAL_SIG_POST },
  { "SIGNAL_USR1_PRE_INIT_WRITE", SIGNAL_WRITE },
  { "SIGNAL_USR1_POST_INIT_WRITE", SIGNAL_WRITE | SIGNAL_SIG_POST },
  { "SIGNAL_INT_PRE_INIT_READ", SIGNAL_INT },
  { "SIGNAL_INT_POST_INIT_READ", SIGNAL_INT | SIGNAL_SIG_POST },
  { "SIGNAL_INT_PRE_INIT_WRITE", SIGNAL_INT | SIGNAL_WRITE },
  { "SIGNAL_INT_POST_INIT_WRITE", SIGNAL_INT | SIGNAL_WRITE |
                                  SIGNAL_SIG_POST },
  { NULL, -1 } };

/* signal_socket */
#define SIGSOCK_SOCK_POST       0x01
#define SIGSOCK_SIG_POST        0x02
#define SIGSOCK_DGRAM           0x04
#define SIGSOCK_INT             0x08
#define SIGSOCK_RECV            0x10
static struct map_entry signal_socket_map[] =
{ { "SOCK_PRE_SIG_USR1_PRE_STREAM_SEND", 0 },
  { "SOCK_PRE_SIG_USR1_POST_STREAM_SEND", SIGSOCK_SIG_POST },
  { "SOCK_POST_SIG_USR1_POST_STREAM_SEND", SIGSOCK_SOCK_POST |
                                           SIGSOCK_SIG_POST },
  { "SOCK_PRE_SIG_USR1_PRE_DGRAM_SEND", SIGSOCK_DGRAM },
  { "SOCK_PRE_SIG_USR1_POST_DGRAM_SEND", SIGSOCK_SIG_POST | SIGSOCK_DGRAM },
  { "SOCK_POST_SIG_USR1_POST_DGRAM_SEND", SIGSOCK_SIG_POST |
                                          SIGSOCK_SOCK_POST |
                                          SIGSOCK_DGRAM },
  { "SOCK_PRE_SIG_INT_PRE_STREAM_SEND", SIGSOCK_INT },
  { "SOCK_PRE_SIG_INT_POST_STREAM_SEND", SIGSOCK_INT | SIGSOCK_SIG_POST },
  { "SOCK_POST_SIG_INT_POST_STREAM_SEND", SIGSOCK_SOCK_POST |
                                          SIGSOCK_SIG_POST |
                                          SIGSOCK_INT },
  { "SOCK_PRE_SIG_INT_PRE_DGRAM_SEND", SIGSOCK_INT | SIGSOCK_DGRAM },
  { "SOCK_PRE_SIG_INT_POST_DGRAM_SEND", SIGSOCK_SIG_POST | SIGSOCK_DGRAM |
                                        SIGSOCK_INT },
  { "SOCK_POST_SIG_INT_POST_DGRAM_SEND", SIGSOCK_SIG_POST |
                                         SIGSOCK_SOCK_POST |
                                         SIGSOCK_DGRAM | SIGSOCK_INT },
  { "SOCK_PRE_SIG_USR1_PRE_STREAM_RECV", SIGSOCK_RECV },
  { "SOCK_PRE_SIG_USR1_POST_STREAM_RECV", SIGSOCK_SIG_POST |
                                          SIGSOCK_RECV },
  { "SOCK_POST_SIG_USR1_POST_STREAM_RECV", SIGSOCK_SOCK_POST |
                                           SIGSOCK_SIG_POST |
                                           SIGSOCK_RECV },
  { "SOCK_PRE_SIG_USR1_PRE_DGRAM_RECV", SIGSOCK_DGRAM | SIGSOCK_RECV },
  { "SOCK_PRE_SIG_USR1_POST_DGRAM_RECV", SIGSOCK_SIG_POST | SIGSOCK_DGRAM |
                                         SIGSOCK_RECV },
  { "SOCK_POST_SIG_USR1_POST_DGRAM_RECV", SIGSOCK_SIG_POST |
                                          SIGSOCK_SOCK_POST |
                                          SIGSOCK_DGRAM |
                                          SIGSOCK_RECV },
  { "SOCK_PRE_SIG_INT_PRE_STREAM_RECV", SIGSOCK_INT | SIGSOCK_RECV },
  { "SOCK_PRE_SIG_INT_POST_STREAM_RECV", SIGSOCK_INT | SIGSOCK_SIG_POST |
                                         SIGSOCK_RECV },
  { "SOCK_POST_SIG_INT_POST_STREAM_RECV", SIGSOCK_SOCK_POST |
                                          SIGSOCK_SIG_POST |
                                          SIGSOCK_INT |
                                          SIGSOCK_RECV },
  { "SOCK_PRE_SIG_INT_PRE_DGRAM_RECV", SIGSOCK_INT | SIGSOCK_DGRAM |
                                       SIGSOCK_RECV },
  { "SOCK_PRE_SIG_INT_POST_DGRAM_RECV", SIGSOCK_SIG_POST | SIGSOCK_DGRAM |
                                        SIGSOCK_INT | SIGSOCK_RECV },
  { "SOCK_POST_SIG_INT_POST_DGRAM_RECV", SIGSOCK_SIG_POST |
                                         SIGSOCK_SOCK_POST |
                                         SIGSOCK_DGRAM | SIGSOCK_INT |
                                         SIGSOCK_RECV },
  { NULL, -1 } };

/* thread_fork */
#define THRFORK_SOCKET          0x01
#define THRFORK_DGRAM           0x02
#define THRFORK_RECV            0x04
static struct map_entry thread_fork_map[] =
{ { "WRITE_ON_PIPE", 0 },
  { "SOCK_POST_STREAM_SEND", THRFORK_SOCKET },
  { "SOCK_POST_DGRAM_SEND", THRFORK_SOCKET | THRFORK_DGRAM },
  { "SOCK_POST_STREAM_RECV", THRFORK_SOCKET | THRFORK_RECV },
  { "SOCK_POST_DGRAM_RECV", THRFORK_SOCKET | THRFORK_DGRAM |
                            THRFORK_RECV },
  { NULL, -1 } };

/* atfork */
#define ATFORK_SOCK_POST        0x01
#define ATFORK_DGRAM            0x02
#define ATFORK_RECV             0x04
static struct map_entry atfork_map[] =
{ { "SOCK_PRE_STREAM_SEND", 0 },
  { "SOCK_POST_STREAM_SEND", ATFORK_SOCK_POST },
  { "SOCK_PRE_DGRAM_SEND", ATFORK_DGRAM },
  { "SOCK_POST_DGRAM_SEND", ATFORK_SOCK_POST | ATFORK_DGRAM },
  { "SOCK_PRE_STREAM_RECV", ATFORK_RECV },
  { "SOCK_POST_STREAM_RECV", ATFORK_SOCK_POST | ATFORK_RECV },
  { "SOCK_PRE_DGRAM_RECV", ATFORK_DGRAM | ATFORK_RECV },
  { "SOCK_POST_DGRAM_RECV", ATFORK_SOCK_POST | ATFORK_DGRAM |
                            ATFORK_RECV},
  { NULL, -1 } };

/**
 * Map iteration name into corresponding set of flags.
 *
 * @param str       Iteration name
 * @param map       Map corresponding to current sequence name
 *
 * @return  Set of flags defined above
 */
static int
resolve_mapping(char *str, struct map_entry *map)
{
    int i;
    for (i = 0; map[i].name != NULL; i++)
        if (strcmp(str, map[i].name) == 0)
            return map[i].value;
    return -1;
}

/**
 * Sequence name:   hello
 *
 * Description:     Basic scenario. Just printing "Hello World!"
 *                  to standard output.
 */
static void
lt_hello_check(void)
{
    CHECK_RC(printf("Hello World!\n"));
    rc = 0;
}

static void
lt_init_hello(void)
{
    if (!(lt_ts.iter & HELLO_PRINT_POST))
        lt_hello_check();
}

static void
lt_do_hello(void)
{
    if (lt_ts.iter & HELLO_PRINT_POST)
        lt_hello_check();
}

/**
 * Sequence name:   popen
 *
 * Description:     _init calls popen() with "echo something" command.
 *                  Later we read from obtained file descriptor.
 */
static void
lt_popen_check(void)
{
    char *tmp;
    tmp = (char *)malloc(test_str_size);

    CHECK_RC(fscanf(lt_tv.popen.fd, "%s", tmp));
    tmp[test_str_size - 1] = '\0';

    rc = strcmp(tmp, test_str);
    free(tmp);
}

static void
lt_init_popen(void)
{
    char *comm;
    comm = (char *)malloc(test_str_size + strlen("echo "));

    strcpy(comm, "echo ");
    strcat(comm, test_str);

    lt_tv.popen.fd = popen(comm, "r");
    if (lt_tv.popen.fd == NULL)
    {
        perror("popen() failed");
        exit(EXIT_FAILURE);
    }

    if (!(lt_ts.iter & POPEN_READ_POST))
        lt_popen_check();
}

static void
lt_do_popen(void)
{
    if (lt_ts.iter & POPEN_READ_POST)
        lt_popen_check();
}

/**
 * Sequence name:   fork_exec
 *
 * Description:     _init executes the analog of popen() function
 *                  by making explicit calls of pipe()+fork()+exec().
 *                  Later we read from obtained file descriptor.
 */
static void
lt_fork_exec_check(void)
{
    char *tmp;
    int n;
    tmp = (char *)malloc(test_str_size);

    CHECK_RC(n = read(lt_tv.fork_exec.pipefd, tmp, test_str_size));
    tmp[test_str_size - 1] = '\0';
    rc = strcmp(tmp, test_str);
    CHECK_RC(close(lt_tv.fork_exec.pipefd));
    free(tmp);
}

static void
lt_init_fork_exec(void)
{
    int     pipefd[2];
    pid_t   pid;

    CHECK_RC(pipe(pipefd));
    CHECK_RC(pid = fork());
    if (pid == 0)
    {
        CHECK_RC(close(pipefd[0]));
        CHECK_RC(dup2(pipefd[1], STDOUT_FILENO));
        CHECK_RC(execlp("echo", "echo", "-n", test_str, (char *)NULL));
    }
    else
    {
        CHECK_RC(close(pipefd[1]));
        lt_tv.fork_exec.pipefd = pipefd[0];
        wait(NULL);
        if (!(lt_ts.iter & FORKEXEC_READ_POST))
            lt_fork_exec_check();
    }
}

static void
lt_do_fork_exec(void)
{
    if (lt_ts.iter & FORKEXEC_READ_POST)
        lt_fork_exec_check();
}

/**
 * Sequence name:   pipe
 *
 * Description:     _init calls pipe(). Later we check that obtained file
 *                  descriptors work properly.
 */
static void
lt_pipe_check(void)
{
    char *buf;
    buf = (char *)malloc(test_str_size);

    CHECK_RC(write(lt_tv.pipe.pipefd[1], test_str, test_str_size));
    CHECK_RC(read(lt_tv.pipe.pipefd[0], buf, test_str_size));
    buf[test_str_size - 1] = '\0';

    rc = strcmp(buf, test_str);
    free(buf);
    close(lt_tv.pipe.pipefd[0]);
    close(lt_tv.pipe.pipefd[1]);
}

static void
lt_init_pipe(void)
{
    CHECK_RC(pipe(lt_tv.pipe.pipefd));

    if (!(lt_ts.iter & PIPE_CHECK_POST))
        lt_pipe_check();
}

static void
lt_do_pipe(void)
{
    if (lt_ts.iter & PIPE_CHECK_POST)
        lt_pipe_check();
}

/**
 * Sequence name:   signal
 *
 * Description:     _init installs signal handler. Signal handler calls
 *                  read() or write().
 */

static void
lt_signal_write(void)
{
    CHECK_RC(write(lt_tv.signal.pipefd[1], test_str, test_str_size));
}

static void
lt_signal_read(void)
{
    char *buf;
    buf = (char *)malloc(test_str_size);

    CHECK_RC(read(lt_tv.signal.pipefd[0], buf, test_str_size));
    buf[test_str_size - 1] = '\0';

    rc = strcmp(buf, test_str);
    free(buf);
    close(lt_tv.signal.pipefd[0]);
    close(lt_tv.signal.pipefd[1]);
}

static void
lt_signal_handler(int signum)
{
    UNUSED(signum);
    if (lt_ts.iter & SIGNAL_WRITE)
        lt_signal_write();
    else
        lt_signal_read();
}

static void
lt_signal_check(void)
{
    if (!(lt_ts.iter & SIGNAL_WRITE))
        lt_signal_write();
    CHECK_RC(raise((lt_ts.iter & SIGNAL_INT) ? SIGINT : SIGUSR1));
    if (lt_ts.iter & SIGNAL_WRITE)
        lt_signal_read();
}

static void
lt_init_signal(void)
{
    struct sigaction new_action;

    CHECK_RC(pipe(lt_tv.signal.pipefd));

    new_action.sa_handler = lt_signal_handler;
    sigemptyset(&new_action.sa_mask);
    new_action.sa_flags = 0;

    CHECK_RC(sigaction((lt_ts.iter & SIGNAL_INT) ? SIGINT : SIGUSR1,
                       &new_action, NULL));

    if (!(lt_ts.iter & SIGNAL_SIG_POST))
        lt_signal_check();
}

static void
lt_do_signal(void)
{
    if (lt_ts.iter & SIGNAL_SIG_POST)
        lt_signal_check();
}

/**
 * Sequence name:   signal_socket
 *
 * Description:     _init installs signal handler. Signal handler calls
 *                  send() on a socket.
 */

static inline void
lt_signal_socket_send(void)
{
    CHECK_RC(send(lt_tv.signal_socket.sock, test_str, test_str_size, 0));
    rc = 0;
}

static void
lt_signal_socket_recv(void)
{
    char *buf;
    int n;

    buf = (char *)malloc(test_str_size + 1);
    sleep(LT_TIMING_DELAY); /* Sleep for 1s for data to arrive */
    CHECK_RC(n = recv(lt_tv.signal_socket.sock, buf,
                      test_str_size, 0));
    buf[n] = '\0';

    rc = strcmp(buf, test_str);
    free(buf);
}

static void
lt_signal_socket_handler(int signum)
{
    UNUSED(signum);
    if (lt_ts.iter & SIGSOCK_RECV)
        lt_signal_socket_recv();
    else
        lt_signal_socket_send();
}

static void
lt_signal_socket_create(void)
{
    int sock_type;

    sock_type = (lt_ts.iter & SIGSOCK_DGRAM) ? SOCK_DGRAM : SOCK_STREAM;

    GENERATE_CONNECTION(lt_tv.signal_socket.sock, sock_type,
                        lt_ts.iter & SIGSOCK_RECV);
}

static void
lt_signal_socket_check(void)
{
    CHECK_RC(raise((lt_ts.iter & SIGSOCK_INT) ? SIGINT : SIGUSR1));
}

static void
lt_init_signal_socket(void)
{
    struct sigaction new_action;

    lt_tv.signal_socket.sock = -1;

    new_action.sa_handler = lt_signal_socket_handler;
    CHECK_RC(sigemptyset(&new_action.sa_mask));
    new_action.sa_flags = 0;

    CHECK_RC(sigaction((lt_ts.iter & SIGSOCK_INT) ? SIGINT : SIGUSR1,
                       &new_action, NULL));

    if (!(lt_ts.iter & SIGSOCK_SOCK_POST))
        lt_signal_socket_create();

    if (!(lt_ts.iter & SIGSOCK_SIG_POST))
        lt_signal_socket_check();
}

static void
lt_do_signal_socket(void)
{
    if (lt_ts.iter & SIGSOCK_SOCK_POST)
        lt_signal_socket_create();

    if (lt_ts.iter & SIGSOCK_SIG_POST)
        lt_signal_socket_check();

    SOCKET_CLOSE(lt_tv.signal_socket.sock);
}

/**
 * Sequence name:   thread_fork
 *
 * Description:     _init creates a thread, which forks.  The child,
 *                  kicked by do(), performs the following:
 *                  - calls some write() functions for already-existing fd;
 *                  - creates socket and uses it.
 */

static void
lt_thread_fork_send(int sock)
{
    CHECK_RC(send(sock, test_str, test_str_size, 0));
    rc = 0;
}

static void
lt_thread_fork_recv(int sock)
{
    char *buf;
    int n;

    buf = (char *)malloc(test_str_size + 1);

    sleep(LT_TIMING_DELAY); /* Sleep for 1s for data to arrive */
    CHECK_RC(n = recv(sock, buf, test_str_size, 0));
    buf[n] = '\0';

    rc = strcmp(buf, test_str);
    free(buf);
}

static void
lt_thread_fork_handler(int signum)
{
    UNUSED(signum);
    if (lt_ts.iter & THRFORK_SOCKET)
    {
        int sock_type;
        int sock;

        sock_type = (lt_ts.iter & THRFORK_DGRAM) ? SOCK_DGRAM :
                                                   SOCK_STREAM;
        GENERATE_CONNECTION(sock, sock_type,
                            lt_ts.iter & THRFORK_RECV);

        if (lt_ts.iter & THRFORK_RECV)
            lt_thread_fork_recv(sock);
        else
            lt_thread_fork_send(sock);

        SOCKET_CLOSE(sock);
    }
    else
    {
        CHECK_RC(write(lt_tv.thread_fork.pipefd[1], test_str,
                       test_str_size));
        rc = 0;
    }

}

static void *
lt_thread_fork_thread(void *data)
{
    pid_t child;

    UNUSED(data);

    CHECK_RC(child = fork());
    if (child == 0)
    {
        struct sigaction new_action;

        rc = -1;

        new_action.sa_handler = lt_thread_fork_handler;
        sigemptyset(&new_action.sa_mask);
        new_action.sa_flags = 0;

        CHECK_RC(sigaction(SIGUSR1, &new_action, NULL));

        /* Sleep untill the signal is raised */
        sleep(15);

        exit(rc);
    }
    else
    {
        lt_tv.thread_fork.child = child;
        pthread_exit(NULL);
    }
}

static void
lt_init_thread_fork(void)
{
    pthread_t thread;
    pthread_attr_t attr;

    if (!(lt_ts.iter & THRFORK_SOCKET))
        CHECK_RC(pipe(lt_tv.thread_fork.pipefd));

    CHECK_RC(pthread_attr_init(&attr));
    CHECK_RC(pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_JOINABLE));
    CHECK_RC(pthread_create(&thread, &attr, lt_thread_fork_thread, NULL));
    CHECK_RC(pthread_join(thread, NULL));
    sleep(LT_TIMING_DELAY); /* Sleep for 1s to let child set up signal handler */
    CHECK_RC(pthread_attr_destroy(&attr));
}

static void
lt_do_thread_fork(void)
{
    CHECK_RC(kill(lt_tv.thread_fork.child, SIGUSR1));
    if (lt_ts.iter & THRFORK_SOCKET)
    {
        rc = lt_tv.thread_fork.child;
    }
    else
    {
        char *buf;
        buf = (char *)malloc(test_str_size);

        CHECK_RC(read(lt_tv.thread_fork.pipefd[0], buf, test_str_size));
        buf[test_str_size - 1] = '\0';

        rc = strcmp(buf, test_str);
        free(buf);
    }
}

/**
 * Sequence name:   atfork
 *
 * Description:     _init() installs fork() hooks with pthread_atfork().
 *                  Hooks call send/recv functions on sockets, created in
 *                  pre- or post-init time.
 */
static void
lt_atfork_create_sockets(void)
{
    int sock_type;

    sock_type = (lt_ts.iter & ATFORK_DGRAM) ? SOCK_DGRAM : SOCK_STREAM;

    GENERATE_CONNECTION(lt_tv.atfork.sock, sock_type,
                        lt_ts.iter & ATFORK_RECV);
}

static void
lt_atfork_send(void)
{
    CHECK_RC(send(lt_tv.atfork.sock, test_str, test_str_size, 0));
    rc = 0;
}

static void
lt_atfork_recv(void)
{
    char *buf;
    int n;

    buf = (char *)malloc(test_str_size + 1);

    sleep(LT_TIMING_DELAY); /* Sleep for 1s for data to arrive */
    CHECK_RC(n = recv(lt_tv.atfork.sock, buf,
                      test_str_size, 0));
    buf[n] = '\0';

    rc = strcmp(buf, test_str);
    free(buf);
}

static void
lt_atfork_handler(void)
{
    if (lt_ts.iter & ATFORK_RECV)
        lt_atfork_recv();
    else
        lt_atfork_send();
}

static void
lt_init_atfork(void)
{
    lt_tv.atfork.sock = -1;

    pthread_atfork(NULL, NULL, lt_atfork_handler);

    if (!(lt_ts.iter & ATFORK_SOCK_POST))
        lt_atfork_create_sockets();
}

static void
lt_do_atfork(void)
{
    int child;

    if (lt_ts.iter & ATFORK_SOCK_POST)
        lt_atfork_create_sockets();

    CHECK_RC(child = fork());
    if(child == 0)
        exit(rc);
    else
        rc = child;

    SOCKET_CLOSE(lt_tv.signal_socket.sock);
}


/**
 * Remove any entry of library name from LD_PRELOAD
 */
static void
clear_ld_preload(void)
{
    char *buf, *env, *tmp, *tok;
    int n = 0;

    env = getenv("LD_PRELOAD");
    if (env == NULL)
        return;

    buf = (char *)malloc((strlen(env) + 1));
    buf[0] = '\0';

    for (tmp = strdup(env); (tok = strtok(tmp, ":")) != NULL; tmp = NULL)
    {
        if (strstr(tok, LT_LIBRARY_NAME) == NULL)
        {
            strcpy(buf + n, tok);
            n += strlen(tok);
            buf[n++] = ':';
            buf[n]   = '\0';
        }
    }

    setenv("LD_PRELOAD", buf, 1);

    free(tmp);
    free(buf);
}

/* IF_CASE macro should be defined before using this macro. */
#define SWITCH_SEQUENCE \
    do {                                \
        IF_CASE(popen);                 \
        else IF_CASE(fork_exec);        \
        else IF_CASE(pipe);             \
        else IF_CASE(signal);           \
        else IF_CASE(signal_socket);    \
        else IF_CASE(thread_fork);      \
        else IF_CASE(atfork);           \
        else IF_CASE(hello);            \
    } while(0)

__attribute__((constructor))
static void
_init(void)
{
    const char *init_ts;
    char        iter[LT_MAX_SEQ_LEN];

    clear_ld_preload();
    rc = -1;
    init_ts = getenv("LIBINIT_TEST_SEQ");

    if(init_ts == NULL)
    {
        snprintf(lt_ts.seq, LT_MAX_SEQ_LEN, "hello");
        lt_ts.iter = 0;
    }
    else
        CHECK_RC(sscanf(init_ts, "%s %s", lt_ts.seq, iter));

    test_str = getenv("LIBINIT_TEST_STR");
    if (test_str == NULL)
        test_str = LT_TEST_STR;
    test_str_size = strlen(test_str) + 1;

#define IF_CASE(_case) \
    if (strcmp(lt_ts.seq, #_case) == 0)     \
        CHECK_RC(lt_ts.iter = resolve_mapping(iter, _case ## _map))
    SWITCH_SEQUENCE;
#undef IF_CASE

#define IF_CASE(_case) \
    if (strcmp(lt_ts.seq, #_case) == 0)     \
        return lt_init_ ## _case()
    SWITCH_SEQUENCE;
#undef IF_CASE
}

int
lt_do(void)
{
#define IF_CASE(_case) \
    if (strcmp(lt_ts.seq, #_case) == 0)     \
        lt_do_ ## _case()
    SWITCH_SEQUENCE;
#undef IF_CASE
    return rc;
}
#undef SWITCH_SEQUENCE
