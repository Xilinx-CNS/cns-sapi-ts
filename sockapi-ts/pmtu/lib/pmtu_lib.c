/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/* 
 * Socket API Test Suite
 * Path MTU change handling
 * 
 * $Id$
 */

#include "te_config.h"

#include <ctype.h>

#include "te_defs.h"
#include "te_printf.h"

#define TE_TEST_NAME  "pmtu/pmtu_lib"
#include "logger_api.h"

#include "sockapi-test.h"
#include "icmp_send.h"
#include "pmtu_lib.h"

#define PMTU_SCENARIO_SIZE_MAX      32
#define PMTU_SEQ_CAPACITY_INC_VALUE 100

#define PART_BUFF_LEN               1963
#define SENDFILE_TEST_BUFFER_SIZE   113

#define PMTU_SEND_PATTERN_BASE(id)  (((id) & 0xf) << 4)
#define PMTU_SEND_PATTERN_INTERVAL  (1 << 4)

#define PMTU_SEND_SEQ_ID(x)         (((x) >> 4) & 0xf)

#define PMTU_SEND_PATTERN_CHECK(x, off) (((x) & 0xf) == pmtu_send_pattern(off))

#define PMTU_RPC_TIMEOUT            120

#define PMTU_MTU_SEQ_SIZE_MAX       128

#define PMTU_MTU_SEQ_SIZE_MIN       4

#define PMTU_ICMP_PATTERN_LEN_MAX   128

#define PMTU_WAIT_FOR_ICMP_TIMEOUTS_MAX     30
#define PMTU_WAIT_FOR_ICMP_TIMEOUT          1

#define PMTU_ICMP_NEXT_HOP_MTU_OFFSET   (14 + 20 + 6)

/** Maximum possible number of writev blocks in one function call */
#define PMTU_WRITEV_BLOCKS_MAX      10

/** File name for the sendfile to use on the agent */
#define PMTU_AGENT_FILENAME "te_ta_pmtu_sendfile"
/** File name for the sendfile to use on the engine */
#define PMTU_ENGINE_FILENAME "te_pmtu_sendfile"

/** Number of function calls for statistics */
#define STATISTIC_ITERATION_LIMIT 1000

/**
 * Display statistics with the number of calls and the size of processed
 * data
 *
 * @param func_         Function name (e.g. writev/sys_writev)
 * @param iteration_    Iteration number
 * @param current_      Total quantity of the processed data at the moment
 *                      in bytes
 * @param last_         Total quantity of the processed data at the first
 *                      iteration in bytes
 */
#define STATISTIC_PRINT(func_, iteration_, current_, last_) \
    do {                                                    \
        const uint64_t total = (current_) - (last_);        \
        RING("%s:%d: is called %llu times and "             \
             "processed %llu bytes of data",                \
             (func_), __LINE__, (iteration_), total);       \
    } while (0)

/**
 * Display statistics first time and every @b STATISTIC_ITERATION_LIMIT
 * calls
 *
 * @param func_         Function name (e.g. writev/sys_writev)
 * @param iteration_    Iteration number
 * @param current_      Total quantity of the processed data by the moment
 *                      in bytes
 * @param last_         Total quantity of the processed data to 0 iteration
 */
#define STATISTIC_STEP(func_, iteration_, current_, last_)          \
    do {                                                            \
        (iteration_)++;                                             \
        if ((iteration_) >= STATISTIC_ITERATION_LIMIT ||            \
            (last_) == 0)                                           \
        {                                                           \
            STATISTIC_PRINT(func_, iteration_, current_, last_);    \
            (last_) = (current_);                                   \
            (iteration_) = 0;                                       \
        }                                                           \
    } while (0)

/**
 * Acquire a lock before reading/updating fields of the thread
 * structure which can be accessed from outside of the thread.
 *
 * @param _th     Pointer to pmtu_thread structure.
 */
#define THREAD_LOCK(_th) \
    do {                                                            \
        int _rc = pthread_mutex_lock(&(_th)->lock);                 \
        if (_rc != 0)                                               \
        {                                                           \
            TEST_FAIL("pthread_mutex_lock() returned %d for "       \
                      "thread %d", _rc, (_th)->id);                 \
        }                                                           \
    } while (0)

/**
 * Release a lock after reading/updating fields of the thread
 * structure which can be accessed from outside of the thread.
 *
 * @param _th     Pointer to pmtu_thread structure.
 */
#define THREAD_UNLOCK(_th) \
    do {                                                            \
        int _rc = pthread_mutex_unlock(&(_th)->lock);               \
        if (_rc != 0)                                               \
        {                                                           \
            TEST_FAIL("pthread_mutex_unlock() returned %d for "     \
                      "thread %d", _rc, (_th)->id);                 \
        }                                                           \
    } while (0)

/**
 * Acquire a lock before reading/updating fields of the scenario
 * structure which can be accessed from threads.
 *
 * @param _scenario     Pointer to pmtu_scenario structure.
 */
#define SCENARIO_LOCK(_scenario) \
    do {                                                            \
        int _rc = pthread_mutex_lock(&(_scenario)->lock);           \
        if (_rc != 0)                                               \
        {                                                           \
            TEST_FAIL("pthread_mutex_lock() returned %d for "       \
                      "scenario lock", _rc);                        \
        }                                                           \
    } while (0)

/**
 * Release a lock after reading/updating fields of the scenario
 * structure which can be accessed from threads.
 *
 * @param _scenario     Pointer to pmtu_scenario structure.
 */
#define SCENARIO_UNLOCK(_scenario) \
    do {                                                            \
        int _rc = pthread_mutex_unlock(&(_scenario)->lock);         \
        if (_rc != 0)                                               \
        {                                                           \
            TEST_FAIL("pthread_mutex_unlock() returned %d for "     \
                      "scenario lock", _rc);                        \
        }                                                           \
    } while (0)

/**
 * Calculate send/recv pattern (independent per each sending sequence)
 *
 * @param off                   send/recv pattern offset
 *
 * @return byte of pattern corresponding to offset
 */
static inline uint8_t
pmtu_send_pattern(uint64_t off)
{
    return (((off % 47) * (off % 11) + (off % 17) + 7) & 0xf);
}

/**
 * Prepare sending buffer by filling it with data pattern.
 *
 * @param data                  sending buffer
 * @param off                   sending pattern offset
 * @param count                 sending buffer size
 * @param s_id                  sending sequence id
 *
 * @return N/A
 */
static inline void
pmtu_fill_pattern(uint8_t *data, uint64_t off, int count, int s_id)
{
    int i;

    VERB("%s(%p, %llu, %d, %d) started", __FUNCTION__,
         data, off, count, s_id);

    if ((data == NULL) || (count < 0) || (s_id < 0) || (s_id > 0xf))
    {
        ERROR("Cannot fill data buffer with sending pattern (%p, %d, %d)",
              data, count, s_id);
        return;
    }
    
    for (i = 0; i < count; i++)
    {
        data[i] = PMTU_SEND_PATTERN_BASE(s_id) +
                  pmtu_send_pattern(off + i);
    }
}


/**
 * Prepare remote file on the test agent for sendfile() operation.
 *
 * @param ta                    Test Agent name
 * @param off                   sending pattern offset
 * @param count                 sending buffer size
 * @param s_id                  sending sequence id
 * @param fname                 returned remote file name
 *
 * @return status code
 */
static void
pmtu_prepare_remote_file(const char *ta, uint64_t off, int count,
                         int s_id, char **fname)
{
    int     rc;
    FILE   *file;
    int     len = 0;
    char    buffer[SENDFILE_TEST_BUFFER_SIZE];
    char    path_tmpl[RCF_MAX_PATH];
    char    path_rem[RCF_MAX_PATH];

    VERB("%s(%s, %llu, %d, %d) started", __FUNCTION__,
         ta, off, count, s_id);

    if (ta == NULL || count < 0)
    {
        TEST_FAIL("%s(): invalide parameters", __FUNCTION__);
    }

    snprintf(path_tmpl, sizeof(path_tmpl), "%s"PMTU_ENGINE_FILENAME".%d", 
             getenv("TE_TMP"), s_id);

    file = fopen(path_tmpl, "w");
    if (file == NULL)
    {
        TEST_FAIL("%s(): template file opening failure", __FUNCTION__);
    }

    while (count > 0) {
        len = (count >= SENDFILE_TEST_BUFFER_SIZE) ?
               SENDFILE_TEST_BUFFER_SIZE : count;
        pmtu_fill_pattern((uint8_t *)buffer, off, len, s_id);
        fwrite(&buffer, sizeof(char), len, file);
        count -= len;
        off += len;
    };
    fclose(file);

    if (*fname == NULL)
    {
        snprintf(path_rem, sizeof(path_rem), 
                 TA_TMP_PATH PMTU_AGENT_FILENAME ".%d", s_id);
        *fname = strdup(path_rem);
    }

    rc = rcf_ta_put_file(ta, 0, path_tmpl, *fname);
    if (unlink(path_tmpl))
    {
        TEST_FAIL("removing of %s template file failure, "
                  "errno=%X", path_tmpl, errno);
    }
    if ( rc != 0)
    {
        TEST_FAIL("%s(): passing %s file failure, rc=%X",
                  __FUNCTION__, path_tmpl, rc);
    }
}



#define PMTU_LIBC_FUNC_PREFIX   "sys_"

typedef void *(*thread_func)(void *);

/**
 * Check result returned by sending function.
 *
 * @param _req_len          Length of data passed to the function.
 * @param _rc               Value returned by the function.
 * @param _scenario         Pointer to pmtu_scenario structure.
 * @param _partial_verdict  If @c TRUE, print verdict in case of
 *                          partial send.
 */
#define CHECK_SEND_RC(_req_len, _rc, _scenario, _partial_verdict) \
    do {                                                                \
        if (_rc < _req_len)                                             \
        {                                                               \
            WARN("%s(): partial send occurred: %d bytes were sent "     \
                 "instead of %d", __FUNCTION__, _rc, _req_len);         \
                                                                        \
            if (_partial_verdict)                                       \
            {                                                           \
                SCENARIO_LOCK(_scenario);                               \
                if (!(_scenario)->partial_send)                         \
                    ERROR_VERDICT("Partial send was detected");         \
                (_scenario)->partial_send = TRUE;                       \
                SCENARIO_UNLOCK(_scenario);                             \
            }                                                           \
        }                                                               \
        else if (_rc > _req_len)                                        \
        {                                                               \
            TEST_FAIL("%s(): sending function returned too big "        \
                    "value: %d instead of %d",  __FUNCTION__,           \
                    _rc, _req_len);                                     \
        }                                                               \
    } while (0)

/**
 * Function to start a thread sending data with send-like function.
 *
 * @param thread_p  pointer to thread data structure
 *
 * @return should be ignored
 */
static void *
pmtu_thread_send(void *thread_p)
{
    pmtu_thread   *th =(pmtu_thread *) thread_p;
    pmtu_scenario *scenario = th->scenario;
    int            maxbufsize = scenario->sndbuf / 4;
    char          *buf = malloc(maxbufsize);
    uint64_t       counter = 0;
    uint64_t       last_sent = th->sent;

    TAPI_ON_JMP(th->scenario->stop = TRUE;
                STATISTIC_PRINT(th->func_name, counter, th->sent,
                                last_sent);
                return NULL;);
    if (buf == NULL)
        TEST_FAIL("Out of memory");

    th->pco_send->start = scenario->start;
    while(!scenario->stop)
    {
        int size = rand_range(maxbufsize / 2, maxbufsize);
        int rc;

        pmtu_fill_pattern((uint8_t *)buf, th->sent, size, th->id);

        THREAD_LOCK(th);
        th->queued = size;
        THREAD_UNLOCK(th);

        rc = ((rpc_send_f)th->func)(th->pco_send,
                                    scenario->send_s, buf, size, 0);
        CHECK_SEND_RC(size, rc, scenario, TRUE);
        THREAD_LOCK(th);
        th->sent += rc;
        th->queued = 0;
        THREAD_UNLOCK(th);

        STATISTIC_STEP(th->func_name, counter, th->sent, last_sent);
    }

    TAPI_JMP_POP;
    STATISTIC_PRINT(th->func_name, counter, th->sent, last_sent);

    THREAD_LOCK(th);
    th->stopped = TRUE;
    THREAD_UNLOCK(th);
    return NULL;
}

/**
 * Function to start a thread sending data with writev-like function.
 *
 * @param thread_p  pointer to thread data structure
 *
 * @return should be ignored
 */
static void *
pmtu_thread_writev(void *thread_p)
{
    pmtu_thread   *th =(pmtu_thread *) thread_p;
    pmtu_scenario *scenario = th->scenario;
    rpc_iovec      vector[PMTU_WRITEV_BLOCKS_MAX];
    int            maxbufsize = scenario->sndbuf / 4;
    int            block;
    uint64_t       counter = 0;
    uint64_t       last_sent = th->sent;

    TAPI_ON_JMP(th->scenario->stop = TRUE;
                STATISTIC_PRINT(th->func_name, counter, th->sent,
                                last_sent);
                return NULL;);
    for (block = 0; block < PMTU_WRITEV_BLOCKS_MAX; block++)
    {
        vector[block].iov_base = malloc(maxbufsize / 2);
        if (vector[block].iov_base == NULL)
            TEST_FAIL("Out of  memory");
    }

    th->pco_send->start = scenario->start;
    while(!scenario->stop)
    {
        int count = rand_range(2, PMTU_WRITEV_BLOCKS_MAX - 1);
        int total_size = 0;
        int rc;

        for (block = 0; block < count; block++)
        {
            int size = rand_range(maxbufsize / (count * 2),
                                  maxbufsize / count);

            vector[block].iov_len = vector[block].iov_rlen = size;
            pmtu_fill_pattern(vector[block].iov_base, th->sent + total_size,
                              size, th->id);
            total_size += size;
        }

        THREAD_LOCK(th);
        th->queued = total_size;
        THREAD_UNLOCK(th);

        rc = rpc_writev(th->pco_send, scenario->send_s, vector, count);
        CHECK_SEND_RC(total_size, rc, scenario, TRUE);
        THREAD_LOCK(th);
        th->sent += rc;
        th->queued = 0;
        THREAD_UNLOCK(th);

        STATISTIC_STEP(th->func_name, counter, th->sent, last_sent);
    }

    TAPI_JMP_POP;
    STATISTIC_PRINT(th->func_name, counter, th->sent, last_sent);

    THREAD_LOCK(th);
    th->stopped = TRUE;
    THREAD_UNLOCK(th);
    return NULL;
}

/**
 * Function to start a thread sending data with sendfile-like function.
 *
 * @param thread_p  pointer to thread data structure
 *
 * @return should be ignored
 */
static void *
pmtu_thread_sendfile(void *thread_p)
{
    pmtu_thread   *th =(pmtu_thread *) thread_p;
    pmtu_scenario *scenario = th->scenario;
    int            maxbufsize = scenario->sndbuf / 2;
    uint64_t       counter = 0;
    uint64_t       last_sent = th->sent;

    TAPI_ON_JMP(th->scenario->stop = TRUE;
                STATISTIC_PRINT(th->func_name, counter, th->sent,
                                last_sent);
                return NULL;);

    th->pco_send->start = scenario->start;
    while(!scenario->stop)
    {
        int         size = rand_range(maxbufsize / 2, maxbufsize);
        int         fd;
        tarpc_off_t off = 0;
        int         count = rand_range(2, PMTU_WRITEV_BLOCKS_MAX);
        int         cur_count;
        int         rc;

        pmtu_prepare_remote_file(th->pco_send->ta, th->sent, size, th->id, 
                                 &th->filename);
        th->pco_send->silent = TRUE;
        fd = rpc_open(th->pco_send, th->filename, RPC_O_RDONLY, 0);
        while (off < size)
        {
            cur_count = MIN(size - off,
                            rand_range(size / (2 * count),
                                       size / count));

            THREAD_LOCK(th);
            th->queued = cur_count;
            THREAD_UNLOCK(th);
            rc = rpc_sendfile(th->pco_send, scenario->send_s, fd, &off,
                              cur_count, FALSE);

            /*
             * For sendfile() partial sending is fine, according to
             * Linux manual it is normal for this function; it often
             * happens both on pure Linux and Onload here.
             */
            CHECK_SEND_RC(cur_count, rc, scenario, FALSE);
            THREAD_LOCK(th);
            th->queued = 0;
            th->sent += rc;
            THREAD_UNLOCK(th);
        }
        th->pco_send->silent = TRUE;
        rpc_close(th->pco_send, fd);
        rcf_ta_del_file(th->pco_send->ta, 0, th->filename);

        STATISTIC_STEP(th->func_name, counter, th->sent, last_sent);
    }

    TAPI_JMP_POP;
    STATISTIC_PRINT(th->func_name, counter, th->sent, last_sent);

    THREAD_LOCK(th);
    th->stopped = TRUE;
    THREAD_UNLOCK(th);
    return NULL;
}

/**
 * Choose sending function to start a sending thread with it based on the
 * function name. Set information used by this function into scenario
 * structure.
 *
 * @param func_name     function name to use when sending data
 * @param th            sending thread info
 *
 * @return function to pass to pthread_create
 */
static thread_func
pmtu_choose_sending_func(const char *func_name, pmtu_thread *th)
{
    th->func_name = strdup(func_name);

    /* Check if we should use libc for this function */
    if (strncmp(func_name, PMTU_LIBC_FUNC_PREFIX,
                strlen(PMTU_LIBC_FUNC_PREFIX)) == 0)
    {
        func_name += strlen(PMTU_LIBC_FUNC_PREFIX);
        th->pco_send->use_libc = TRUE;
    }

    if (strcmp(func_name, "writev") == 0)
    {
        th->func = rpc_writev;
        return &pmtu_thread_writev;
    }
    else 
    if ((th->func = rpc_send_func_by_string(func_name)) != NULL)
    {
        return &pmtu_thread_send;
    }
    else if (strcmp(func_name, "sendfile") == 0)
    {
        th->func = rpc_sendfile;
        return &pmtu_thread_sendfile;
    }
    else
    {
        TEST_FAIL("Unknown function \"%s\" in send_params", func_name);
        return NULL; /* To make gcc happy */
    }
}

/**
 * Create a TCP connection and start threads sending data in accordance 
 * with @p send_params.
 *
 * @param pco_send      PCO to send data
 * @param snd_addr      address to send from
 * @param rcv_addr      address to receive on
 * @param send_params   list of functions to be used when sending data
 * @param scenario      status of the process to return to user
 * @param passive       Use or do not use passive connection
 */
void
pmtu_start_sending_threads(rcf_rpc_server *pco_send, 
                    const struct sockaddr *snd_addr,
                    const struct sockaddr *rcv_addr,
                    char **send_params, pmtu_scenario *scenario,
                    te_bool passive)
{
    int             id;
    int             accept_s;

    scenario->recv_s = rpc_socket(scenario->pco_recv,
                                  rpc_socket_domain_by_addr(rcv_addr),
                                  RPC_SOCK_STREAM, RPC_PROTO_DEF);
    rpc_bind(scenario->pco_recv, scenario->recv_s, rcv_addr);

    scenario->send_s = rpc_socket(pco_send,
                                  rpc_socket_domain_by_addr(snd_addr),
                                  RPC_SOCK_STREAM, RPC_PROTO_DEF);
    rpc_bind(pco_send, scenario->send_s, snd_addr);

    rpc_setsockopt(pco_send, scenario->send_s, RPC_SO_SNDBUF,
                   &scenario->sndbuf);
    rpc_setsockopt(scenario->pco_recv, scenario->recv_s,
                   RPC_SO_RCVBUF, &scenario->rcvbuf);
    scenario->pco_recv->def_timeout *= 4;

    if (passive)
    {
        rpc_listen(pco_send, scenario->send_s, SOCKTS_BACKLOG_DEF);
        rpc_connect(scenario->pco_recv, scenario->recv_s, snd_addr);
        accept_s = rpc_accept(pco_send, scenario->send_s, NULL, NULL);
        RPC_CLOSE(pco_send, scenario->send_s);
        scenario->send_s = accept_s;
    }
    else
    {
        rpc_listen(scenario->pco_recv, scenario->recv_s, SOCKTS_BACKLOG_DEF);
        rpc_connect(pco_send, scenario->send_s, rcv_addr);
        accept_s = rpc_accept(scenario->pco_recv, scenario->recv_s, NULL, NULL);
        RPC_CLOSE(scenario->pco_recv, scenario->recv_s);
        scenario->recv_s = accept_s;
    }

    if (pthread_mutex_init(&scenario->lock, NULL) != 0)
        TEST_FAIL("Failed to initialize scenario lock");
    scenario->partial_send = FALSE;

    scenario->threads = calloc(scenario->threads_num, sizeof(pmtu_thread));
    /* Start sending threads */
    for (id = 0; id < scenario->threads_num; id++)
    {
        char         pco_name[20];
        pmtu_thread *th = &scenario->threads[id];

        if (pthread_mutex_init(&th->lock, NULL) != 0)
            TEST_FAIL("Failed to initialize thread lock");

        /* Set up RPC server. */
        th->id = id;
        sprintf(pco_name, "src_chld%d", id);

        /*
         * Threads are no longer used on TA here since Onload does not
         * handle multithreading properly, see ON-4658.
         */
        if (rcf_rpc_server_fork(pco_send, pco_name, &th->pco_send))
            TEST_FAIL("Cannot spawn more RPC servers");
        th->pco_send->def_timeout *= 10 * scenario->threads_num;
        th->pco_send->timeout = th->pco_send->def_timeout;
        th->sent = th->received = 0;
        th->stopped = FALSE;

        th->scenario = scenario;
        if (pthread_create(&th->thread, NULL, 
                           pmtu_choose_sending_func(send_params[id], th), 
                           th) 
            != 0)
        {
            TEST_FAIL("Failed to create thread");
        }
    }
}

/**
 * Receive data and check it correctness.
 *
 * @param scenario  state of send/receive scenario
 * @param buf       buffer to use for receiving
 * @param buflen    length of the buffer
 * @param mask      bitmask with threads which received data (OUT)
 *
 * @return amount of received data
 */
int
pmtu_recv_and_check(pmtu_scenario *scenario, char *buf, int buflen, 
                    uint32_t *mask)
{
    int  rc;
    int  i;

    if (mask != NULL)
        *mask = 0;
    rc = rpc_recv(scenario->pco_recv, scenario->recv_s, buf, buflen, 0);

    for (i = 0; i < rc; i++)
    {
        int      id = PMTU_SEND_SEQ_ID(buf[i]);
        uint64_t off = scenario->threads[id].received;
        uint64_t sent;
        uint64_t queued;

        if (id >= scenario->threads_num)
            TEST_FAIL("Corrupted data received");
        if (!PMTU_SEND_PATTERN_CHECK(buf[i], off))
        {
            TEST_FAIL("Invalid byte sequence received, "
                      "thread %d, bytes received %llu, "
                      "expecting 0x%x, got 0x%x",
                      id, off,
                      PMTU_SEND_PATTERN_BASE(id) + pmtu_send_pattern(off),
                      buf[i]);
        }

        THREAD_LOCK(&scenario->threads[id]);
        sent = scenario->threads[id].sent;
        queued = scenario->threads[id].queued;
        THREAD_UNLOCK(&scenario->threads[id]);
        if (off >= sent + queued)
        {
            TEST_FAIL("Too much bytes in thread %d: "
                      "sent %llu, queued %llu, received %llu",
                      id, sent, queued, off + 1);
        }

        scenario->threads[id].received++;
        if (mask != NULL)
            *mask |= (1 << id);
    }

    return rc;
}

/* See description in pmtu_lib.h */
void
pmtu_recv_some_data(pmtu_scenario *scenario, uint64_t amount)
{
    uint64_t    recv_bytes = 0;
    char       *buf;
    int         buflen = scenario->rcvbuf / 2;

    uint64_t       counter = 0;
    uint64_t       last_recv = 0;
    struct timeval time_start;
    struct timeval time_current;

    /* bitmask to find threads which did not send anything */
    int incomplete = (1 << scenario->threads_num) - 1; 

    buf = malloc(buflen);
    if (buf == NULL)
        TEST_FAIL("Out of memory");
    gettimeofday(&time_start, NULL);
    while (!scenario->stop && (incomplete != 0 || recv_bytes < amount))
    {
        uint32_t mask;
        int      size;

        if (scenario->stop)
        {
            TEST_FAIL("Test failed because of error when sending data. "
                      "See messages above for details.");
        }
        size = rand_range(1, buflen);
        recv_bytes += pmtu_recv_and_check(scenario, buf, size, &mask);
        incomplete &= ~mask;

        if (scenario->timeout != 0)
        {
            gettimeofday(&time_current, NULL);
            if ((uint64_t)(time_current.tv_sec - time_start.tv_sec) >
                    scenario->timeout)
                break;
        }

        STATISTIC_STEP("recv", counter, recv_bytes, last_recv);
    }
    free(buf);
    STATISTIC_PRINT("recv", counter, recv_bytes, last_recv);
    if (incomplete == 0 && recv_bytes >= amount)
    {
        RING("%llu bytes of data was received by a couple of recv() "
             "functions (%llu)",
             recv_bytes, amount);
    }
    else if (incomplete != 0)
    {
        TEST_FAIL("Test failed because data has not been received from "
                  "one or more senders "
                  "(thread mask: 0x%x, receive: %llu (expected > %llu))",
                  incomplete, recv_bytes, amount);
    }
    else if (recv_bytes < amount)
    {
        TEST_FAIL("Test failed because it received less then necessary "
                  "amount of data (receive: %llu (expected >= %llu))",
                  recv_bytes, amount);
    }
}

/**
 * Stop all sending threads, receive all data and destroy RPC servers.
 *
 * @param scenario  state of send/receive scenario
 */
void
pmtu_finish(pmtu_scenario *scenario)
{
    int      id;
    unsigned buflen = scenario->rcvbuf;
    char    *buf;

    unsigned int attempts;
    unsigned int max_attempts = 100;

    RING("Stop all sending threads, receive all data and check it.");

    /* Stop sending data */
    scenario->stop = TRUE;

    /* Receive all data */
    buf = malloc(buflen);
    if (buf == NULL)
        TEST_FAIL("Engine is out of memory");
    while(1)
    {
        int id;
        te_bool thread_stopped;
        te_bool not_stopped;
        te_bool readable;
        te_bool incomplete;
        uint64_t sent;

        attempts = 0;
        readable = FALSE;
        do {
            if (attempts > max_attempts)
            {
                TEST_VERDICT("Too many attempts were made to wait for "
                             "termination of all the threads without "
                             "any new data being sent from them");
            }

            incomplete = FALSE;
            not_stopped = FALSE;
            for (id = 0; id < scenario->threads_num; id++)
            {
                THREAD_LOCK(&scenario->threads[id]);
                sent = scenario->threads[id].sent;
                thread_stopped = scenario->threads[id].stopped;
                THREAD_UNLOCK(&scenario->threads[id]);
                INFO("Thread %d: sent %llu, received %llu", id,
                     sent, scenario->threads[id].received);
                if (sent != scenario->threads[id].received)
                    incomplete = TRUE;
                if (!thread_stopped)
                    not_stopped = TRUE;
            }

            if (!not_stopped && !incomplete)
                break;

            /*
             * Better to check for readability before trying to receive
             * something to avoid recv() hanging until RPC timeout and
             * print a normal verdict instead. Also this introduces
             * some waiting before rechecking all the threads again.
             */
            RPC_GET_READABILITY(readable, scenario->pco_recv,
                                scenario->recv_s, TAPI_WAIT_NETWORK_DELAY);
            if (readable)
                break;

            attempts++;
        } while (TRUE);

        if (!readable)
            break;

        pmtu_recv_and_check(scenario, buf, buflen, NULL);
    }
    rpc_close(scenario->pco_recv, scenario->recv_s);
    scenario->recv_s = -1;

    /* Wait for sending threads to exit */
    for (id = 0; id < scenario->threads_num; id++)
    {
        void *ret;

        if (scenario->threads[id].thread != 0)
        {
            pthread_join(scenario->threads[id].thread, &ret);
            scenario->threads[id].thread = 0;
        }
        free(scenario->threads[id].func_name);
    }

    for (id = 0; id < scenario->threads_num; id++)
    {
        if (scenario->threads[id].sent != scenario->threads[id].received)
        {
            ERROR("In thread %d there is mismatch between sent and "
                  "received data: sent %llu bytes, received %llu bytes",
                  id, scenario->threads[id].sent,
                  scenario->threads[id].received);
            TEST_VERDICT("Number of bytes received differs from number "
                         "of bytes sent");
        }
    }
}
