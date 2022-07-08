/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/** @file
 * @brief Socket API Test Suite
 *
 * Implementation of auxiliary functions for sending and receiving
 * data.
 *
 * @author Dmitry Izbitsky <Dmitry.Izbitsky@oktetlabs.ru>
 */

#include "sockapi-test.h"
#include "rpc_sendrecv.h"

/* See description in rpc_sendrecv.h */
ssize_t
sockts_recv_by_zc_recv(rcf_rpc_server *rpcs, int s,
                       char *rx_buf, int len, int msgs_num,
                       rpc_send_recv_flags flags)
{
#define MSGS_NUM SOCKTS_RECV_BY_ZC_RECV_MAX_MSGS
#define BUFS_PER_MSG 5
#define BUF_LEN 3000
    char                bufs[MSGS_NUM][BUFS_PER_MSG][BUF_LEN];
    rpc_iovec           vectors[MSGS_NUM][BUFS_PER_MSG];
    int                 i;
    int                 j;
    int                 pos = 0;
    int                 rc;

    struct rpc_onload_zc_mmsg mmsgs[MSGS_NUM];

    /*
     * onload_zc_recv() does not work like recvmsg(): callback is passed
     * to it which then processes retrieved buffers, each up to about 1500
     * bytes long. These buffers are retrieved in separate iovecs by
     * rpc_simple_zc_recv(). So passing the single big buffer to it does not
     * work, it will not be fully filled.
     * If multiple packets are received, callback is called for each packet
     * separately, and iovec buffers for each packet will be reported in a
     * separate message. So we may need multiple messages as well here,
     * especially in case of TCP where the single send() call may result in
     * multiple packets being sent.
     */

    if (msgs_num < 0)
        msgs_num = MSGS_NUM;
    if (msgs_num > MSGS_NUM)
    {
        ERROR("%s(): too many messages were requested", __FUNCTION__);
        rpcs->_errno = TE_RC(TE_TAPI, TE_EINVAL);
        return -1;
    }

    memset(&mmsgs, 0, sizeof(mmsgs));
    for (i = 0; i < msgs_num; i++)
    {
        mmsgs[i].msg.msg_iov = vectors[i];
        mmsgs[i].msg.msg_iovlen =
                      mmsgs[i].msg.msg_riovlen = BUFS_PER_MSG;
        mmsgs[i].msg.msg_flags_mode = RPC_MSG_FLAGS_SET_CHECK;

        for (j = 0; j < BUFS_PER_MSG; j++)
        {
            vectors[i][j].iov_base = bufs[i][j];
            vectors[i][j].iov_len = BUF_LEN;
            vectors[i][j].iov_rlen = BUF_LEN;
        }
    }

    rc = rpc_simple_zc_recv_gen(rpcs, s, mmsgs, msgs_num, NULL, flags,
                                NULL, TRUE);
    if (rc < 0)
    {
        return rc;
    }
    else
    {
        for (i = 0; i < msgs_num; i++)
        {
            if (mmsgs[i].rc > 0)
            {
                if (mmsgs[i].rc > len - pos)
                {
                    ERROR("%s(): too small buffer provided",
                          __FUNCTION__);
                    rpcs->_errno = TE_RC(TE_TAPI, TE_ESMALLBUF);
                    return -1;
                }

                iovecs_to_buf(mmsgs[i].msg.msg_iov,
                              mmsgs[i].msg.msg_iovlen,
                              rx_buf + pos, mmsgs[i].rc);
                pos += mmsgs[i].rc;
            }
        }
    }

    return pos;
#undef BUFS_PER_MSG
#undef MSGS_NUM
#undef BUF_LEN
}
