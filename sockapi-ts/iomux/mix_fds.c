/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/* 
 * Socket API Test Suite
 * I/O Multiplexing
 */

/** @page iomux-mix_fds Mixture of different file descriptors
 *
 * @objective Check that I/O multiplexing functions correctly handles
 *            mixture of file descriptors.
 *
 * @param pco_iut   PCO on IUT
 * @param pco_tst   PCO on TESTER
 * @param iut_addr  Network address on IUT
 * @param tst_addr  Network address on TESTER
 * @param n_fds     Number of file descriptors of each type to be created
 * @param iomux     I/O multiplexing function to be tested
 *
 * @par Scenario:
 * -# Open @p n_fds file descriptors (pairs) of each type in random order:
 *      - @b pipe() - pair of file descriptors (one for reading and
 *        another for writing);
 *      - @b socketpair() - pair of indistinguishable socket file
 *        descriptors in @c AF_UNIX domain of @c SOCK_STREAM or
 *        @c SOCK_DGRAM type with default protocol;
 *      - @b socket() - TCP or UDP socket;
 *      - @b stdin - file descriptor is equal to 0;
 *      - @b stdout - file descriptor is equal to 1;
 *      - @b stderr - file descriptor is equal to 2;
 *      - @b open("/dev/zero", O_RDONLY) -
 *        character device ready for reading;
 *      - @b open("/dev/null", O_WRONLY) -
 *        character device ready for writing;
 *      - @b open("/tmp/te_tmp_file_XXXXXX", O_RDWR | O_CREAT, S_IRWXU) -
 *        descriptor of an ordinary file;
 *      .
 *    Save created file descriptors in an array with auxiluary information
 *    about them and their pairs (if appropriate).
 * -# Call @p iomux function.
 * -# Check returned events and return value of @p iomux function.
 * -# Send data to each fd for which it is possible. 
 * -# Call @p iomux function again.
 * -# Check returned events and return value of @p iomux function.
 *
 * @note
 *  -# @anchor note_writable 
 *  All file descriptors (even input pipe fd's, file-stream descriptors, etc)
 *  in Unix are detected as writable by I/O multiplexing 
 *  functions, except cases with full output buffer. 
 *  -# @anchor note_pipes
 *  Pipes on BSD are bi-directional, therefore both descriptors are writable. 
 *  Pipes on Linux has strange feature (bug?): after write before respective 
 *  read both sockets are readable but not writable. 
 *
 * @author Dmitry Izbitsky <Dmitry.Izbitsky@oktetlabs.ru>
 * @author Andrew Rybchenko <Andrew.Rybchenko@oktetlabs.ru>
 * @author Konstantin Abramenko <Konstantin.Abramenko@oktetlabs.ru>
 */

#define TE_TEST_NAME "iomux/mix_fds"

#include "sockapi-test.h"
#include "iomux.h"
#include "onload.h"

typedef enum {
    FD_UNKNOWN = 0,
    FD_DEV_NULL,
    FD_DEV_ZERO,
    FD_STDIN,
    FD_STDOUT,
    FD_STDERR,
    FD_PIPE_R_LIBC,
    FD_PIPE_R,
    FD_PIPE_W_LIBC,
    FD_PIPE_W,
    FD_SOCKETPAIR_DGM,
    FD_SOCKETPAIR_STR,
    FD_TMPFILE, 
    FD_TCPCONN_LIBC,
    FD_TCPCONN,
    FD_UDPCONN_LIBC,
    FD_UDPCONN,
} fd_type;

#define TYPES_NUM (FD_UDPCONN + 1)

typedef struct fd_info {
    int             fd;
    int             fd_pair;
    rcf_rpc_server *pco_pair;
    char           *fname;
    fd_type         type;
    te_bool         is_onload;
} fd_info;

#define MAX_STR 1000

typedef struct fd_type_verdicts {
    char **verdicts;
    int   *processed;
    int    count;
} fd_type_verdicts;

rcf_rpc_server             *pco_iut = NULL;
static iomux_call_type      iomux;
static te_bool              epoll_tested = FALSE;
static unsigned int         n_fds = 0;
static fd_info             *fds_info = NULL;
static iomux_evt_fd        *iomux_fds = NULL;
static fd_type_verdicts     type_verdicts[TYPES_NUM];
static char                *type_name[TYPES_NUM];
static int                  exp_iomux_rc;
static te_bool              is_failed = FALSE;
/**
 * This will be set to @c TRUE if iomux returns no events
 * for all the system fds.
 */
static te_bool              nononload_noevents;
static te_bool              onload_evts_disabled = FALSE;

static inline void
onload_fds_disable_evts()
{
    int     i = 0;
    char    buf[MAX_STR];
    te_bool readable;

    for (i = 0; i < (int)n_fds; i++)
    {
        if (fds_info[i].is_onload)
        {
            if (fds_info[i].type != FD_PIPE_R) 
            {
                if (fds_info[i].type == FD_UDPCONN)
                    iomux_fds[i].events &= ~EVT_WR;
                else if (fds_info[i].type != FD_PIPE_W) 
                    rpc_overfill_buffers(pco_iut, fds_info[i].fd,
                                         NULL);
                else
                    rpc_overfill_fd(pco_iut, fds_info[i].fd, NULL);
            }

            if (fds_info[i].type != FD_PIPE_W) 
            {
                while (TRUE)
                {
                    RPC_GET_READABILITY(readable, pco_iut, fds_info[i].fd,
                                        1000);
                    if (!readable)
                        break;
                    rpc_read(pco_iut, fds_info[i].fd, buf, MAX_STR);
                }
            }
        }
    }

    onload_evts_disabled = TRUE;
}

static inline void
onload_fds_enable_evts()
{
    int     i = 0;
    char    buf[MAX_STR];
    te_bool readable;

    for (i = 0; i < (int)n_fds; i++)
    {
        if (fds_info[i].is_onload)
        {
            if (fds_info[i].type != FD_PIPE_R) 
            {
                if (fds_info[i].type == FD_UDPCONN)
                    iomux_fds[i].events |= EVT_WR;
                else 
                {
                    while (TRUE)
                    {
                        RPC_GET_READABILITY(readable, fds_info[i].pco_pair,
                                            fds_info[i].fd_pair, 500);
                        if (!readable)
                            break;
                        rpc_read(fds_info[i].pco_pair, fds_info[i].fd_pair,
                                 buf, MAX_STR);
                    }
                }
            }
        }
    }

    onload_evts_disabled = FALSE;
}

static inline void
free_verdicts()
{
    int i;
    int j;

    for (i = 0; i < TYPES_NUM; i++)
    {
        for (j = 0; j < type_verdicts[i].count; j++)
            free(type_verdicts[i].verdicts[j]);
        free(type_verdicts[i].verdicts);
        free(type_verdicts[i].processed);
        type_verdicts[i].verdicts = NULL;
        type_verdicts[i].processed = NULL;
        type_verdicts[i].count = 0;
    }
}

static inline void
add_verdict(fd_type type, char *verdict)
{
    void    *p;
    int      i;

    for (i = 0; i < type_verdicts[type].count; i++)
        if (strcmp(type_verdicts[type].verdicts[i], verdict) == 0)
            break;

    if (i < type_verdicts[type].count)
        return;

    p = realloc(type_verdicts[type].verdicts,
                (++type_verdicts[type].count) * sizeof(char *));
    if (p == NULL)
        TEST_FAIL("Impossible to reallocate memory for verdicts");
    type_verdicts[type].verdicts = p;

    p = realloc(type_verdicts[type].processed,
                type_verdicts[type].count * sizeof(int));
    if (p == NULL)
        TEST_FAIL("Impossible to reallocate memory for processed "
                  "array");
    type_verdicts[type].processed = p;

    if ((type_verdicts[type].verdicts[i] = strdup(verdict)) == NULL)
        TEST_FAIL("Impossible to duplicate '%s'", verdict);
    type_verdicts[type].processed[i] = 0;
}

static inline int
get_exp_events(fd_type type, te_bool peer_wrote)
{
    int evts = 0;

    switch (type)
    {
        case FD_DEV_NULL:
        case FD_DEV_ZERO:
            evts = EVT_RD | EVT_WR;
            break;

        case FD_STDIN:
            evts = (iomux == IC_SELECT || iomux == IC_PSELECT) ?
                        EVT_RD : (EVT_EXC | EVT_HUP);
            break;

        case FD_STDOUT:
        case FD_STDERR:
        case FD_PIPE_W:
        case FD_PIPE_W_LIBC:
            evts = EVT_WR;
            break;

        case FD_PIPE_R:
        case FD_PIPE_R_LIBC:
            evts = peer_wrote ? EVT_RD : 0;
            break;

        case FD_SOCKETPAIR_DGM:
        case FD_SOCKETPAIR_STR:
        case FD_TCPCONN:
        case FD_TCPCONN_LIBC:
        case FD_UDPCONN:
        case FD_UDPCONN_LIBC:
            evts = peer_wrote ? (EVT_RD | EVT_WR) : EVT_WR;
            break;

        case FD_TMPFILE:
            evts = EVT_RD | EVT_WR;
            break;

        default:
            evts = 0;
            break;
    }

    return evts;
}

static inline int
evts_to_rc(int evts)
{
    if (iomux != IC_SELECT && iomux != IC_PSELECT)
        return evts > 0 ? 1 : 0;
    else
        return ((evts & EVT_RD) ? 1 : 0) +
               ((evts & EVT_WR) ? 1 : 0) +
               ((evts & EVT_EXC) ? 1 : 0);
}

static inline void
check_events(te_bool peer_wrote)
{
    int     i;
    int     exp_evts;
    char    verdict[MAX_STR];

    exp_iomux_rc = 0;

    if (n_fds > 0)
        nononload_noevents = TRUE;

    for (i = 0; i < (int)n_fds; i++)
    {
        exp_iomux_rc += evts_to_rc(iomux_fds[i].revents);

        exp_evts = get_exp_events(fds_info[i].type, peer_wrote);

        if (onload_evts_disabled && fds_info[i].is_onload)
            exp_evts = 0;

        if (!((fds_info[i].is_onload &&
               exp_evts == iomux_fds[i].revents) || 
              (!fds_info[i].is_onload &&
               iomux_fds[i].revents == 0)))
            nononload_noevents = FALSE;

        if (exp_evts != iomux_fds[i].revents)
        {
            snprintf(verdict, MAX_STR, "expected events %s but got %s",
                     iomux_event_rpc2str(exp_evts),
                     iomux_event_rpc2str(iomux_fds[i].revents));
            add_verdict(fds_info[i].type, verdict);
        }
        else
            add_verdict(fds_info[i].type, "");
    }
}

static inline void
print_verdicts(char *msg, ...)
{
    fd_type  type;
    char    *scope;
    int      i;
    int      j;
    int      k;
    char     text[MAX_STR];
    va_list  arg;
    char     verdict[MAX_STR];
    int      n;

    va_start(arg, msg);
    vsnprintf(text, MAX_STR, msg, arg);
    va_end(arg);

    for (type = 0; type < TYPES_NUM; type++)
    {
        if (type_verdicts[type].count == 1)
            scope = "for all";
        else
            scope = "for some";

        /**
         * Here we try to print any unique verdict only once
         * if it should be printed for several different file
         * types.
         */
        for (i = 0; i < type_verdicts[type].count; i++)
        {
            if (type_verdicts[type].processed[i] == 0 &&
                strlen(type_verdicts[type].verdicts[i]) > 0)
            {
                n = snprintf(verdict, MAX_STR,
                             "%s%s fds of type(s) '%s'",
                             text, scope, type_name[type]);
                type_verdicts[type].processed[i] = 1;

                for (j = i + 1; j < TYPES_NUM; j++)
                {
                    for (k = 0; k < type_verdicts[j].count; k++)
                    {
                        if (type_verdicts[j].processed[k] == 0 &&
                            strcmp(type_verdicts[j].verdicts[k],
                                   type_verdicts[type].verdicts[i]) == 0 &&
                            (type_verdicts[type].count ==
                                             type_verdicts[j].count ||
                            (type_verdicts[type].count > 1 &&
                             type_verdicts[j].count > 1)))
                        {
                            n += snprintf(verdict + n, MAX_STR - n,
                                          ", '%s'", type_name[j]);
                            type_verdicts[j].processed[k] = 1;
                        }
                    }
                }
                    
                RING_VERDICT("%s %s",
                             verdict,
                             type_verdicts[type].verdicts[i]);
            }
        }
    }
}

static inline te_bool
has_pair(fd_type type)
{
    switch (type)
    {
        case FD_PIPE_R:
        case FD_PIPE_R_LIBC:
        case FD_PIPE_W:
        case FD_PIPE_W_LIBC:
        case FD_SOCKETPAIR_DGM:
        case FD_SOCKETPAIR_STR:
        case FD_TCPCONN:
        case FD_TCPCONN_LIBC:
        case FD_UDPCONN:
        case FD_UDPCONN_LIBC:
            return TRUE;

        default:
            return FALSE;
    }
}

static inline void
write_data()
{
#define DATA_LEN 500

    char data[DATA_LEN];
    int  i = 0;

    for (i = 0; i < (int)n_fds; i++)
    {
        if (has_pair(fds_info[i].type) &&
            fds_info[i].type != FD_PIPE_W &&
            fds_info[i].type != FD_PIPE_W_LIBC)
            rpc_write(fds_info[i].pco_pair, fds_info[i].fd_pair,
                      data, DATA_LEN);
    }

    TAPI_WAIT_NETWORK;
}

#define CALL_CHECK_IOMUX(peer_wrote_, str_...) \
    do {                                                            \
        char text_[MAX_STR];                                        \
        snprintf(text_, MAX_STR, str_);                             \
        RPC_AWAIT_IUT_ERROR(pco_iut);                               \
        rc = iomux_call(iomux, pco_iut, iomux_fds,                  \
                        n_fds, &timeout);                           \
        if (rc < 0)                                                 \
            TEST_VERDICT("Calling %s() %s failed "                  \
                         "with errno %s",                           \
                         iomux_call_en2str(iomux), text_,           \
                         errno_rpc2str(RPC_ERRNO(pco_iut)));        \
                                                                    \
        memset(type_verdicts, 0, sizeof(fd_type_verdicts));         \
                                                                    \
        check_events(peer_wrote_);                                  \
        if (rc != exp_iomux_rc)                                     \
        {                                                           \
            ERROR_VERDICT("Calling iomux_call(%s) %s returned "     \
                          "strange value",                          \
                          iomux_call_en2str(iomux), text_);         \
            is_failed = TRUE;                                       \
        }                                                           \
    } while(0)

/**
 * This macro not only checks what iomux returns but also, if
 * the only problem is not reporting events for all the system fds,
 * it will print only one verdict about it and check that if all the
 * events are disabled on Onload fds, then events for system fds are
 * reported by the next iomux call.
 */
#define IOMUX_CHECK_ONLOAD(peer_wrote_) \
    do {                                                                \
        char *str_;                                                     \
                                                                        \
        if (peer_wrote_)                                                \
            str_ = "after making fds readable";                         \
        else                                                            \
            str_ = "after opening fds";                                 \
                                                                        \
        CALL_CHECK_IOMUX((peer_wrote_), (str_));                        \
                                                                        \
        if (nononload_noevents)                                         \
            RING_VERDICT("When calling iomux %s, "                      \
                         "no events are detected on system fds",        \
                         (str_));                                       \
                                                                        \
        if (!(!te_str_is_null_or_empty(socklib) && nononload_noevents)) \
            print_verdicts("Calling iomux %s: ", (str_));               \
        else                                                            \
        {                                                               \
            free_verdicts();                                            \
            onload_fds_disable_evts();                                  \
            CALL_CHECK_IOMUX((peer_wrote_),                             \
                             "%s with no events on onload fds",         \
                             (str_));                                   \
            print_verdicts("Calling iomux %s with no events on "        \
                           "onload fds: ", (str_));                     \
            onload_fds_enable_evts();                                   \
        }                                                               \
                                                                        \
        free_verdicts();                                                \
    } while (0)

int
main(int argc, char *argv[])
{
    tarpc_timeval   timeout = { 0, 0 };
    rcf_rpc_server *pco_tst = NULL;

    const struct sockaddr         *iut_addr;
    const struct sockaddr         *tst_addr;
    struct sockaddr_storage        iut_addr_aux;
    struct sockaddr_storage        tst_addr_aux;

    fd_type          type;
    int              fd_min[TYPES_NUM];
    int              fd_max[TYPES_NUM];
    int              fd_count[TYPES_NUM];
    int              fd_pair[2];
    int              mins_sum;
    int              n_tmpfiles = 0;

    cfg_val_type     val_type;
    char            *socklib = NULL;
    int              attempts;
    unsigned int     i;
    unsigned int     j;
    int              rc2;

    char msg[MAX_STR];
    char tmp_file_name[100];

    /* Preambule */
    TEST_START;
    TEST_GET_PCO(pco_iut);
    TEST_GET_ADDR(pco_iut, iut_addr);
    TEST_GET_PCO(pco_tst);
    TEST_GET_ADDR(pco_tst, tst_addr);
    TEST_GET_IOMUX_FUNC(iomux);
    TEST_GET_INT_PARAM(n_fds); 

    epoll_tested = (iomux == IC_EPOLL || iomux == IC_OO_EPOLL ||
                    iomux == IC_EPOLL_PWAIT || iomux == IC_EPOLL_PWAIT2);

    iomux_fds = calloc(n_fds, sizeof(iomux_evt_fd));

    timeout.tv_sec = 1;
    timeout.tv_usec = 0;

    for (i = 0; i < n_fds; i++)
        iomux_fds[i].fd = -1;

    fds_info = calloc(n_fds, sizeof(fd_info));

    memset(fd_min, 0, sizeof(fd_min));
    memset(fd_max, 0, sizeof(fd_max));

    val_type = CVT_STRING;
    cfg_get_instance_fmt(&val_type, &socklib,
                         "/local:%s/socklib:", pco_iut->ta);

    /*
     * Here parameters for fds set generation are specified.
     * fd_min[type] - minimum number of fds of this type in the resulting
     * set.
     * fd_max[type] - maximum number of fds of this type in the resulting
     * set.
     */
    type_name[FD_UNKNOWN] = "UNKNOWN";
    fd_min[FD_UNKNOWN] = fd_max[FD_UNKNOWN] = 0;
    fd_min[FD_DEV_NULL] = fd_max[FD_DEV_NULL] = (epoll_tested ? 0 : 1);
    type_name[FD_DEV_NULL] = "/dev/null";
    fd_min[FD_DEV_ZERO] = fd_max[FD_DEV_ZERO] = (epoll_tested ? 0 : 1);
    type_name[FD_DEV_ZERO] = "/dev/zero";
    fd_min[FD_STDIN] = fd_max[FD_STDIN] = 1;
    type_name[FD_STDIN] = "stdin";
    fd_min[FD_STDOUT] = fd_max[FD_STDOUT] = 1;
    type_name[FD_STDOUT] = "stdout";
    fd_min[FD_STDERR] = fd_max[FD_STDERR] = 1;
    type_name[FD_STDERR] = "stderr";
    fd_min[FD_PIPE_R] = 1;
    fd_max[FD_PIPE_R] = -1;
    type_name[FD_PIPE_R] = "read end of pipe";
    type_name[FD_PIPE_R_LIBC] = "read end of libc pipe";
    fd_min[FD_PIPE_W] = 1;
    fd_max[FD_PIPE_W] = -1;
    type_name[FD_PIPE_W] = "write end of pipe";
    type_name[FD_PIPE_W_LIBC] = "write end of libc pipe";
    fd_min[FD_SOCKETPAIR_DGM] = 1;
    fd_max[FD_SOCKETPAIR_DGM] = -1;
    type_name[FD_SOCKETPAIR_DGM] = "datagram PF_UNIX socket";
    fd_min[FD_SOCKETPAIR_STR] = 1;
    fd_max[FD_SOCKETPAIR_STR] = -1;
    type_name[FD_SOCKETPAIR_STR] = "stream PF_UNIX socket";
    fd_min[FD_TMPFILE] = epoll_tested ? 0 : 1;
    fd_max[FD_TMPFILE] = epoll_tested ? 0 : -1;
    type_name[FD_TMPFILE] = "temporary file";
    fd_min[FD_TCPCONN] = 1;
    fd_max[FD_TCPCONN] = -1;
    type_name[FD_TCPCONN] = "TCP socket";
    type_name[FD_TCPCONN_LIBC] = "TCP libc socket";
    fd_min[FD_UDPCONN] = 1;
    fd_max[FD_UDPCONN] = -1;
    type_name[FD_UDPCONN] = "UDP socket";
    type_name[FD_UDPCONN_LIBC] = "UDP libc socket";

    if (!te_str_is_null_or_empty(socklib))
    {
        fd_min[FD_PIPE_R_LIBC] = 1; 
        fd_max[FD_PIPE_R_LIBC] = -1; 
        fd_min[FD_PIPE_W_LIBC] = 1; 
        fd_max[FD_PIPE_W_LIBC] = -1; 
        fd_min[FD_TCPCONN_LIBC] = 1;
        fd_max[FD_TCPCONN_LIBC] = -1;
        fd_min[FD_UDPCONN_LIBC] = 1;
        fd_max[FD_UDPCONN_LIBC] = -1;
    }

    mins_sum = 0;
    for (i = 0; i < TYPES_NUM; i++)
        mins_sum += fd_min[i];

    if (mins_sum > (int)n_fds)
        TEST_FAIL("Not enough file descriptors to test all the required "
                  "types");

    srand(time(NULL));

    attempts = 0;
    j = 0;
    memset(fds_info, 0, sizeof(*fds_info));
    memset(fd_count, 0, sizeof(fd_count));

    /*
     * Randomly generating fds set according to parameters (such as
     * minumum and maximum number of fd of each type.
     */
    while (TRUE)
    {
        attempts++;
        if (attempts > 100000)
            TEST_FAIL("Too many attempts to fill array of fds");
        i = rand() % n_fds; 
        if (fds_info[i].type != FD_UNKNOWN)
            continue;

        type = rand() % (TYPES_NUM - 1) + 1;
        if (fd_count[type] >= fd_min[type] &&
            mins_sum > 0)
            continue;

        if (fd_count[type] == fd_max[type])
            continue;

        if (te_str_is_null_or_empty(socklib) &&
            (type == FD_PIPE_R_LIBC ||
             type == FD_PIPE_W_LIBC ||
             type == FD_TCPCONN_LIBC ||
             type == FD_UDPCONN_LIBC))
            continue;

        fds_info[i].type = type;
        fd_count[type]++;
        if (mins_sum > 0)
            mins_sum--;
        j++;
        if (j == n_fds)
            break;
    }

    for (i = 0; i < n_fds; i++)
    {
        switch (fds_info[i].type)
        {
            case FD_DEV_NULL:
                fds_info[i].fd = rpc_open(pco_iut, "/dev/null",
                                          RPC_O_WRONLY, 0);
                break;

            case FD_DEV_ZERO:
                fds_info[i].fd = rpc_open(pco_iut, "/dev/zero",
                                          RPC_O_RDONLY, 0);
                break;

            case FD_STDIN:
                fds_info[i].fd = RPC_STDIN_FILENO;
                break;

            case FD_STDOUT:
                fds_info[i].fd = RPC_STDOUT_FILENO;
                break;

            case FD_STDERR:
                fds_info[i].fd = RPC_STDERR_FILENO;
                break;

            case FD_PIPE_R_LIBC:
                pco_iut->use_libc_once = TRUE;

            case FD_PIPE_R:
                rpc_pipe(pco_iut, fd_pair);
                fds_info[i].fd = fd_pair[0];
                fds_info[i].fd_pair = fd_pair[1];
                fds_info[i].pco_pair = pco_iut;
                break;

            case FD_PIPE_W_LIBC:
                pco_iut->use_libc_once = TRUE;

            case FD_PIPE_W:
                rpc_pipe(pco_iut, fd_pair);
                fds_info[i].fd = fd_pair[1];
                fds_info[i].fd_pair = fd_pair[0];
                fds_info[i].pco_pair = pco_iut;
                break;

            case FD_SOCKETPAIR_DGM:
            case FD_SOCKETPAIR_STR:
                rpc_socketpair(pco_iut, RPC_PF_UNIX,
                               fds_info[i].type == FD_SOCKETPAIR_DGM ?
                                    RPC_SOCK_DGRAM : RPC_SOCK_STREAM,
                               RPC_PROTO_DEF, fd_pair);
                fds_info[i].fd = fd_pair[0];
                fds_info[i].fd_pair = fd_pair[1];
                fds_info[i].pco_pair = pco_iut;
                break;

            case FD_TMPFILE:
                snprintf(tmp_file_name, sizeof(tmp_file_name), 
                         "/tmp/te_tmp_file_%d_%d", 
                         rand_range(0, 100000), n_tmpfiles++);
                fds_info[i].fname = strdup(tmp_file_name);
                if (fds_info[i].fname == 0)
                    TEST_FAIL("strdup(%s) failed", tmp_file_name);

                fds_info[i].fd = rpc_open(pco_iut, tmp_file_name,
                                          RPC_O_RDWR | RPC_O_CREAT,
                                          RPC_S_IRWXU);
                break;

            case FD_TCPCONN_LIBC:
            case FD_UDPCONN_LIBC:
                pco_iut->use_libc = TRUE;

            case FD_TCPCONN:
            case FD_UDPCONN:
                CHECK_RC(tapi_sockaddr_clone(pco_iut, iut_addr,
                                             &iut_addr_aux));
                CHECK_RC(tapi_sockaddr_clone(pco_tst, tst_addr,
                                             &tst_addr_aux));

                GEN_CONNECTION(pco_iut, pco_tst,
                               fds_info[i].type == FD_TCPCONN ||
                               fds_info[i].type == FD_TCPCONN_LIBC ?
                                    RPC_SOCK_STREAM : RPC_SOCK_DGRAM,
                               RPC_PROTO_DEF,
                               SA(&iut_addr_aux), SA(&tst_addr_aux),
                               &fd_pair[0], &fd_pair[1]);

                pco_iut->use_libc = FALSE;
                fds_info[i].fd = fd_pair[0];
                fds_info[i].fd_pair = fd_pair[1];
                fds_info[i].pco_pair = pco_tst;
                break;

            default:
                TEST_FAIL("Unknown file type %d encountered",
                          fds_info[i].type);
        }

        fds_info[i].is_onload = FALSE;
        if (!te_str_is_null_or_empty(socklib) &&
            tapi_onload_is_onload_fd(pco_iut, fds_info[i].fd))
            fds_info[i].is_onload = TRUE;
    }

    j = 0;
    for (i = 0; i < n_fds; i++) 
    {
        iomux_fds[i].fd = fds_info[i].fd;
        iomux_fds[i].events = EVT_WR | EVT_RD | EVT_EXC; 
        j += snprintf(msg + j, MAX_STR - j, "%s, ",
                      type_name[fds_info[i].type]);
    }

    if (j > 0)
        msg[j - 2] = '\0';

    RING("The following set of descriptors will be tested: {%s}",
         msg);

    /*
     * Calling iomux just after fds opening.
     */

    IOMUX_CHECK_ONLOAD(FALSE);

    /*
     * Making readable fds where it is possible.
     */
    write_data();

    /*
     * Calling iomux after sending data to fds for which it is possible.
     */
    IOMUX_CHECK_ONLOAD(TRUE);

    if (is_failed)
        TEST_STOP;
    TEST_SUCCESS;

cleanup:

    for (i = 0; i < n_fds; i++)
    {
        if (fds_info[i].type == FD_STDIN ||
            fds_info[i].type == FD_STDOUT ||
            fds_info[i].type == FD_STDERR)
            continue;

        CLEANUP_RPC_CLOSE(pco_iut, fds_info[i].fd);
        if (has_pair(fds_info[i].type))
            CLEANUP_RPC_CLOSE(fds_info[i].pco_pair,
                              fds_info[i].fd_pair);
    }

    free(iomux_fds);

    for (i = 0; i < n_fds; i++)
    {
        if (fds_info[i].type != FD_TMPFILE || fds_info[i].fname == NULL)
            continue;

        rc2 = rcf_ta_call(pco_iut->ta, 0, "ta_rtn_unlink", &rc,
                          1 /* argc */, FALSE,
                          RCF_STRING, fds_info[i].fname);

        if ((rc2 != 0) || (rc != 0))
        {
            ERROR("Failed to unlink file '%s' of TA '%s': rc=%r",
                  fds_info[i].fname, pco_iut->ta, (rc2 != 0) ? rc2 : rc);
            result = EXIT_FAILURE;
        }
        free(fds_info[i].fname);
    }

    free(fds_info);

    TEST_END;
}

