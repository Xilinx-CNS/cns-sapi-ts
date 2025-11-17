/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/* (c) Copyright 2023 OKTET Labs Ltd. */
/*
 * Socket API Test Suite
 * Bad Parameters and Boundary Values
 */

/** @page bnbvalue-func_socket_pipe_too_many Limit on the number of opened sockets or pipes
 *
 * @objective Check that the system has a limitation on the number of
 *            opened sockets or pipes in the same process.
 *
 * @type conformance, robustness
 *
 * @reference @ref XNS5 section 8.1
 *
 * @param env           Testing environment:
 *                      - @ref arg_types_env_iut_only
 * @param domain        Socket domain:
 *                      - PF_INET
 *                      - PF_INET6
 * @param sock_type     Type of socket used in the test:
 *                      - - (dash): for iterations @p use_pipe = @c TRUE;
 *                      - SOCK_STREAM
 *                      - SOCK_DGRAM
 * @param pco_iut       PCO on IUT
 * @param use_pipe      If it is @c TRUE test pipe instead of socket.
 *
 * @par Scenario:
 * -# Create socket or pipe on @p pco_iut.
 * -# If the function returned @c 0, repeat step 1.
 *    Otherwise check that it returned @c -1 and @b errno is set to @c EMFILE.
 *
 * @author Yurij Plotnikov <Yurij.Plotnikov@oktetlabs.ru>
 * @author Oleg Kravtsov <Oleg.Kravtsov@oktetlabs.ru>
 */

#define TE_TEST_NAME  "bnbvalue/func_socket_pipe_too_many"

#include "sockapi-test.h"


#define BLK_BUF_SIZE 128
#define MAX_CNT 10

#define BIG_RLIM 4096
#define TST_RLIM 8198

#define CREATE_MANY_FDS_AND_CHECK_ERRNO \
do {                                                                       \
    int i;                                                                 \
    te_bool                 op_done = FALSE;                               \
    do {                                                                   \
        if (use_pipe)                                                      \
        {                                                                  \
            RPC_AWAIT_IUT_ERROR(pco_iut);                                  \
            rc = rpc_pipe(pco_iut, &fds[fds_cur]);                         \
        }                                                                  \
        else if (use_accept)                                               \
        {                                                                  \
            rc = rpc_socket(pco_tst, domain, RPC_SOCK_STREAM,              \
                            RPC_PROTO_DEF);                                \
            rpc_connect(pco_tst, rc, iut_addr);                            \
            fds_tst[fds_cur_tst++] = rc;                                   \
            if (fds_cur_tst == fds_size_tst)                               \
            {                                                              \
                void *new_ptr;                                             \
                                                                           \
                CHECK_NOT_NULL(                                            \
                    new_ptr = realloc(fds_tst,                             \
                                      sizeof(*fds_tst) *                   \
                                        (fds_size_tst += BLK_BUF_SIZE)));  \
                fds_tst = new_ptr;                                         \
            }                                                              \
            pco_iut->op = RCF_RPC_CALL;                                    \
            rc = rpc_accept(pco_iut, aux_s, NULL, NULL);                   \
            i = 0;                                                         \
            rcf_rpc_server_is_op_done(pco_iut, &op_done);                  \
            while(!op_done && i++ < MAX_CNT)                               \
            {                                                              \
                MSLEEP(100);                                               \
                rcf_rpc_server_is_op_done(pco_iut, &op_done);              \
            }                                                              \
            if (!op_done)                                                  \
            {                                                              \
                rcf_rpc_server_restart(pco_iut);                           \
                TEST_VERDICT("accept() is hanging.");                      \
            }                                                              \
            RPC_AWAIT_IUT_ERROR(pco_iut);                                  \
            pco_iut->op = RCF_RPC_WAIT;                                    \
            rc = rpc_accept(pco_iut, aux_s, NULL, NULL);                   \
        }                                                                  \
        else                                                               \
        {                                                                  \
            RPC_AWAIT_IUT_ERROR(pco_iut);                                  \
            rc = rpc_socket(pco_iut, domain, sock_type, RPC_PROTO_DEF);    \
        }                                                                  \
        if (rc < 0)                                                        \
            break;                                                         \
                                                                           \
        if (use_pipe)                                                      \
            fds_cur += 2;                                                  \
        else                                                               \
            fds[fds_cur++] = rc;                                           \
        if (fds_cur == fds_size)                                           \
        {                                                                  \
            void *new_ptr;                                                 \
                                                                           \
            CHECK_NOT_NULL(new_ptr = realloc(fds, sizeof(*fds) *           \
                                             (fds_size += BLK_BUF_SIZE))); \
            fds = new_ptr;                                                 \
        }                                                                  \
    } while (1);                                                           \
    if (rc != -1)                                                          \
    {                                                                      \
        TEST_FAIL("%s() on failure is expected to return -1, "             \
                  "but it returns %d",                                     \
                  use_pipe ? "pipe" : use_accept ? "accept" : "socket",    \
                  rc);                                                     \
    }                                                                      \
    if (fds_cur == 0)                                                      \
    {                                                                      \
        TEST_FAIL("%s() failed to create the first file descriptor",       \
                  use_pipe ? "pipe" : use_accept ? "accept" : "socket");   \
    }                                                                      \
    CHECK_RPC_ERRNO_NOEXIT(pco_iut, RPC_EMFILE, failed,                    \
                    "When there is no available file "                     \
                    "descriptors for the process %s() returns -1, but",    \
                    use_pipe ? "pipe" : "socket");                         \
} while (0);

static int
get_ef_max_packets(rcf_rpc_server *pco)
{
    int val;
    tarpc_onload_stat ostat;
    int s = rpc_socket(pco, RPC_AF_INET, RPC_SOCK_STREAM, RPC_PROTO_DEF);

    rpc_onload_fd_stat(pco, s, &ostat);
    rpc_get_opt_from_orm_json(pco, ostat.stack_id, "EF_MAX_PACKETS", &val);
    rpc_close(pco, s);

    return val;
}

int
main(int argc, char *argv[])
{
    rcf_rpc_server    *pco_iut = NULL;
    rcf_rpc_server    *pco_tst = NULL;
    const struct sockaddr  *iut_addr;

    rpc_socket_type    sock_type;
    int               *fds = NULL;
    int                fds_size = BLK_BUF_SIZE;
    int                fds_cur = 0;
    int               *fds_tst = NULL;
    int                fds_size_tst = BLK_BUF_SIZE;
    int                fds_cur_tst = 0;
    int                aux_s = -1;
    rpc_socket_domain  domain;
    te_bool            use_pipe = FALSE;
    te_bool            use_accept = FALSE;
    const char        *retry;
    char              *old_ef_no_fail = NULL;
    const char        *ef_no_fail = NULL;
    cfg_handle         ef_no_fail_handle = CFG_HANDLE_INVALID;
    const char        *ef_max_end = NULL;
    char               ef_synrecv_max[32];
    cfg_handle         ef_max_end_h = CFG_HANDLE_INVALID;
    char              *old_ef_max_end = NULL;
    cfg_handle         ef_tcp_synrecv_max_h = CFG_HANDLE_INVALID;
    char              *old_ef_tcp_synrecv_max = NULL;
    tarpc_rlimit       rlim;
    int                rlim_nofiles;
    int                loglevel;
    int                failed;
    int                sleep_before_retry;
    cfg_handle ef_max_packets = CFG_HANDLE_INVALID;
    char *old_ef_max_packets = NULL;

    TEST_START;
    TEST_GET_BOOL_PARAM(use_pipe);
    TEST_GET_BOOL_PARAM(use_accept);
    if (!use_pipe)
        TEST_GET_SOCK_TYPE(sock_type);
    TEST_GET_PCO(pco_iut);
    if (use_accept)
    {
        TEST_GET_PCO(pco_tst);
        TEST_GET_ADDR(pco_iut, iut_addr);
    }
    TEST_GET_DOMAIN(domain);
    TEST_GET_STRING_PARAM(ef_no_fail);
    TEST_GET_STRING_PARAM(ef_max_end);
    TEST_GET_INT_PARAM(rlim_nofiles);
    TEST_GET_STRING_PARAM(retry);
    TEST_GET_INT_PARAM(sleep_before_retry);

    if (strcmp(ef_max_end, "0") != 0) {
        ef_max_end_h = sockts_set_env_gen(pco_iut, "EF_MAX_ENDPOINTS",
                                          ef_max_end, &old_ef_max_end, FALSE);
        snprintf(ef_synrecv_max, sizeof(ef_synrecv_max), "%d",
                 atoi(ef_max_end) * 6 / 5);
        ef_tcp_synrecv_max_h =
            sockts_set_env_gen(pco_iut, "EF_TCP_SYNRECV_MAX",
                               ef_synrecv_max,
                               &old_ef_tcp_synrecv_max, FALSE);
    }
    /*
     * The test creates big number of connections consuming a lot of packet
     * memory. We should ensure that EF_MAX_PACKETS is not less than 32768,
     * otherwise the test may fail because of lack of packet buffers.
     */
    if (tapi_onload_run() == TRUE && get_ef_max_packets(pco_iut) < 32768)
    {
        ef_max_packets = sockts_set_env_gen(pco_iut, "EF_MAX_PACKETS", "32768",
                                            &old_ef_max_packets, FALSE);
    }
    ef_no_fail_handle = sockts_set_env(pco_iut, "EF_NO_FAIL", ef_no_fail,
                                           &old_ef_no_fail);
    if (strcmp(ef_no_fail, "0") != 0)
        TAPI_SYS_LOGLEVEL_DEBUG(pco_iut, &loglevel);

    /* Set rlimit.  No need to backout - RPC server is restarted at
     * cleanup. */
    rlim.rlim_max = rlim.rlim_cur = rlim_nofiles;
    rpc_setrlimit(pco_iut, RPC_RLIMIT_NOFILE, &rlim);

    CHECK_NOT_NULL(fds = (int *)malloc(fds_size * sizeof(*fds)));
    CHECK_NOT_NULL(fds_tst = (int *)malloc(fds_size * sizeof(*fds)));

    if (use_accept)
    {
        rlim.rlim_max = rlim.rlim_cur = TST_RLIM;
        rpc_setrlimit(pco_tst, RPC_RLIMIT_NOFILE, &rlim);
        aux_s = rpc_socket(pco_iut, domain, RPC_SOCK_STREAM, RPC_PROTO_DEF);
        rpc_bind(pco_iut, aux_s, iut_addr);
        rpc_listen(pco_iut, aux_s, 0);
    }

    CREATE_MANY_FDS_AND_CHECK_ERRNO;

    if (sleep_before_retry)
        SLEEP(sleep_before_retry);

    if (strcmp(retry, "-") == 0) {
        if (use_accept) {
            CHECK_SOCKET_STATE_AND_RETURN_VERDICT(pco_tst,
                                                  fds_tst[fds_cur],
                                                  NULL, -1,
                                                  STATE_CONNECTED);
        }
        TEST_SUCCESS;
    }
    else if (strcmp(retry, "rlim") == 0) {
        rlim.rlim_max = rlim.rlim_cur = BIG_RLIM;
        rpc_setrlimit(pco_iut, RPC_RLIMIT_NOFILE, &rlim);
    }
    else {
      rpc_close(pco_iut, fds[--fds_cur]);
    }

    /* Linux keeps non-accepted file in backlog */
    if (use_accept) {
      int rc_;
      sockts_socket_state_t state;

      rc_ = sockts_get_socket_state(pco_tst, fds_tst[fds_cur], NULL, -1,
                                    &state);
      if (rc_ < 0)
          TEST_VERDICT("Failed to get status of the last connection");
      if( state == STATE_CONNECTED )
          rpc_accept(pco_iut, aux_s, NULL, NULL);
      else {
          ERROR_VERDICT("Wrong socket tst state, got %s; "
                        "expected STATE_CONNECTED",
                        socket_state2str(state));
          RPC_AWAIT_IUT_ERROR(pco_iut);
          rc = rpc_accept(pco_iut, aux_s, NULL, NULL);
          if (rc >= 0) {
              ERROR_VERDICT("Connection have been broken, but accept() passes.");
              failed = TRUE;
          }
          else
              RING_VERDICT("Connection have been dropped with errno %s",
                           errno_rpc2str(RPC_ERRNO(pco_iut)));
      }
    }

    CREATE_MANY_FDS_AND_CHECK_ERRNO;

    if (failed)
      TEST_STOP;
    TEST_SUCCESS;

cleanup:
    CLEANUP_RPC_CLOSE(pco_iut, aux_s);
    while ((--fds_cur) >= 0)
    {
        CLEANUP_RPC_CLOSE(pco_iut, fds[fds_cur]);
    }
    free(fds);
    while ((--fds_cur_tst) >= 0)
    {
        CLEANUP_RPC_CLOSE(pco_tst, fds_tst[fds_cur_tst]);
    }
    free(fds_tst);

    if (strcmp(ef_no_fail, "0") != 0)
        TAPI_SYS_LOGLEVEL_CANCEL_DEBUG(pco_iut, loglevel);

    CLEANUP_CHECK_RC(sockts_restore_env_gen(pco_iut, ef_max_end_h,
                                        old_ef_max_end, FALSE));
    CLEANUP_CHECK_RC(sockts_restore_env_gen(pco_iut, ef_tcp_synrecv_max_h,
                                        old_ef_tcp_synrecv_max, FALSE));
    if (ef_max_packets != CFG_HANDLE_INVALID)
    {
        CLEANUP_CHECK_RC(sockts_restore_env_gen(pco_iut, ef_max_packets,
                                                old_ef_max_packets, FALSE));
    }
    CLEANUP_CHECK_RC(sockts_restore_env(pco_iut, ef_no_fail_handle,
                                        old_ef_no_fail));
    TEST_END;
}
