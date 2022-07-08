/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/** @file
 * @brief Socket API Test Suite
 *
 * Prologue for timestamps package
 *
 * @author Andrey Dmitrov <Andrey.Dmitrov@oktetlabs.ru>
 *
 * $Id$
 */

#define TE_TEST_NAME "timestamps/prologue"

#include "sockapi-test.h"
#include "tapi_sfptpd.h"
#include "tapi_ntpd.h"
#include "timestamps.h"
#include "onload.h"
#include "lib-ts_netns.h"
#include "lib-ts_timestamps.h"

/**
 * Maximum waiting time to get NIC synced, seconds.
 * In theory synchronization can take up to 20 minutes.
 */
#define SYNC_TIME_LIMIT (60*25)

#define MAX_DIFF 1000
#define SUCC_ATTEMPTS_NUM 10


int
main(int argc, char *argv[])
{
    rcf_rpc_server *pco_iut = NULL;
    rcf_rpc_server *pco_tst = NULL;
    const struct sockaddr *iut_addr;
    const struct sockaddr *tst_addr;
    const struct if_nameindex *iut_if;

    te_bool ef_ts_rep_ext;
    te_bool onload;
    te_bool start_sfptpd = !tapi_getenv_bool("ST_RUN_TS_NO_SFPTPD");

    rpc_onload_scm_timestamping_stream *ts_tx;
    rpc_hwtstamp_config                 hw_cfg;
    rpc_scm_timestamping                ts;

    struct cmsghdr *cmsg = NULL;
    rpc_msghdr     *msg = NULL;
    char           *tx_buf = NULL;
    char           *ta_sfc = NULL;
    size_t          buf_len;
    rpc_socket_type sock_type;

    int ef_ts_rep = 0;
    int flags;
    int iut_s = -1;
    int tst_s = -1;
    int count = 0;

    struct timeval tv_start;
    struct timeval tv_end;

    TEST_START;
    TEST_GET_PCO(pco_iut);
    TEST_GET_PCO(pco_tst);
    TEST_GET_ADDR(pco_iut, iut_addr);
    TEST_GET_ADDR(pco_tst, tst_addr);
    TEST_GET_IF(iut_if);

    flags = RPC_SOF_TIMESTAMPING_TX_HARDWARE |
            RPC_SOF_TIMESTAMPING_RX_HARDWARE |
            RPC_SOF_TIMESTAMPING_RX_SOFTWARE |
            RPC_SOF_TIMESTAMPING_RAW_HARDWARE |
            RPC_SOF_TIMESTAMPING_SYS_HARDWARE |
            RPC_SOF_TIMESTAMPING_SOFTWARE;

    onload = tapi_onload_lib_exists(pco_iut->ta);
    if (onload)
    {
        sock_type = RPC_SOCK_STREAM;
        flags |= RPC_ONLOAD_SOF_TIMESTAMPING_STREAM;
        tx_buf = sockts_make_buf_stream(&buf_len);
    }
    else
    {
        sock_type = RPC_SOCK_DGRAM;
        memset(&hw_cfg, 0, sizeof(hw_cfg));
        hw_cfg.tx_type = RPC_HWTSTAMP_TX_ON;
        hw_cfg.rx_filter = RPC_HWTSTAMP_FILTER_ALL;
        CHECK_RC(ioctl_set_ts(pco_iut->ta, iut_if->if_name, &hw_cfg));
        tx_buf = sockts_make_buf_dgram(&buf_len);
    }

    msg = te_calloc_fill(1, sizeof(*msg), 0);
    ts_init_msghdr(TRUE, msg, buf_len);

    CHECK_RC(tapi_sh_env_save_set_int(pco_iut, "EF_TX_TIMESTAMPING", 1,
                                      FALSE, NULL, NULL));
    CHECK_RC(tapi_sh_env_save_set_int(pco_iut, "EF_RX_TIMESTAMPING", 1,
                                      FALSE, NULL, NULL));
    CHECK_RC(tapi_sh_env_save_set_int(pco_iut, "EF_TIMESTAMPING_REPORTING", 1,
                                      FALSE, &ef_ts_rep_ext, &ef_ts_rep));

    sockts_recreate_onload_stack(pco_iut);
    rcf_rpc_server_restart(pco_iut);

    libts_timestamps_enable_sfptpd(pco_iut);
    CHECK_RC(libts_netns_get_sfc_ta(&ta_sfc));

    GEN_CONNECTION(pco_tst, pco_iut, sock_type, RPC_PROTO_DEF,
                   tst_addr, iut_addr, &tst_s, &iut_s);

    rpc_setsockopt(pco_iut, iut_s, RPC_SO_TIMESTAMPING, &flags);

    rc = gettimeofday(&tv_start, NULL);
    if (rc < 0)
        TEST_FAIL("gettimeofday() failed");

    /* Send a packet and retrieve TX timestamps until ts with non-zero
     * hwtimetrans field is obtained.
     */
    while (TRUE)
    {
        rc = gettimeofday(&tv_end, NULL);
        if (rc < 0)
            TEST_FAIL("gettimeofday() failed");
        if (TE_US2SEC(TIMEVAL_SUB(tv_end, tv_start)) >= SYNC_TIME_LIMIT)
            break;

        if (start_sfptpd && !tapi_sfptpd_status(ta_sfc))
            TEST_VERDICT("sfptpd is disabled");

        if (!onload)
        {
            rpc_send(pco_tst, tst_s, tx_buf, buf_len, 0);
            msg->msg_controllen = SOCKTS_CMSG_LEN;
            rpc_recvmsg(pco_iut, iut_s, msg, 0);
            cmsg = sockts_msg_lookup_control_data(msg, SOL_SOCKET,
                                        sockopt_rpc2h(RPC_SO_TIMESTAMPING));
            if (cmsg != NULL)
            {
                memcpy(&ts, CMSG_DATA(cmsg), sizeof(ts));
                ts_print_sys(&ts);
                if (ts_timespec_diff_us(&ts.systime,
                                        &ts.hwtimeraw) < MAX_DIFF)
                {
                    count++;
                    if (count > SUCC_ATTEMPTS_NUM)
                        TEST_SUCCESS;
                }
                else
                    count = 0;
            }
        }
        else
        {
            rpc_send(pco_iut, iut_s, tx_buf, buf_len, 0);
            rpc_recv(pco_tst, tst_s, tx_buf, buf_len, 0);
            TAPI_WAIT_NETWORK;

            memset(msg->msg_control, 0, SOCKTS_CMSG_LEN);
            msg->msg_controllen = SOCKTS_CMSG_LEN;

            RPC_AWAIT_IUT_ERROR(pco_iut);
            rc = rpc_recvmsg(pco_iut, iut_s, msg, RPC_MSG_ERRQUEUE);
            if (rc < 0 && RPC_ERRNO(pco_iut) != RPC_EAGAIN)
                TEST_FAIL("recvmsg failed with unexpected error %s",
                              errno_rpc2str(RPC_ERRNO(pco_iut)));

            if (rc < 0)
                continue;

            cmsg = sockts_msg_lookup_control_data(msg, SOL_SOCKET,
                           sockopt_rpc2h(RPC_ONLOAD_SCM_TIMESTAMPING_STREAM));

            if (cmsg == NULL)
            {
                if (msg->msg_controllen > 0)
                    TEST_FAIL("Obtained cmsg has unexpected type %d");
                TEST_FAIL("cmsg was not found");
            }

            ts_tx = (rpc_onload_scm_timestamping_stream *)CMSG_DATA(cmsg);
            ts_print_tcp_tx(ts_tx);

            if (!ts_timespec_is_zero(&ts_tx->first_sent))
                TEST_SUCCESS;
        }
    }

    TEST_VERDICT("NIC is not synced yet, perhaps there is a problem with "
                 "sfptpd");

cleanup:
    free(tx_buf);
    sockts_release_msghdr(msg);
    CLEANUP_RPC_CLOSE(pco_iut, iut_s);
    CLEANUP_RPC_CLOSE(pco_tst, tst_s);

    CLEANUP_CHECK_RC(tapi_sh_env_rollback_int(pco_iut,
        "EF_TIMESTAMPING_REPORTING", ef_ts_rep_ext, ef_ts_rep,TRUE));

    TEST_END;
}
