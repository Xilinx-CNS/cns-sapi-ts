/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/* 
 * Socket API Test Suite
 * Advanced usage of send/receive functions
 * 
 * $Id$
 */

/** @page sendrecv-lib-two_threads_simultaneous Two thread use a socket for sent/receive operations simultaneously
 *
 * @objective Check robustness of Socket API sent/receive functionality
 *            when two thread use one socket simultaneously.
 *
 * @type stress
 *
 * @param iut       PCO with IUT
 * @param iut_s     a socket on @b iut PCO
 * @param tst       auxiluary PCO
 * @param tst_s     a socket on @b tst PCO
 * @param fork      if true, call @ref lib-create_child_process_socket instead 
 *                  creation of the thread
 *
 * -# Create additional thread in @b iut PCO process. PCO located in
 *    created thread is referred as @b iut2 PCO below.
 *    \n @htmlonly &nbsp; @endhtmlonly
 * -# Simultaneously run remote routines with specified below parameters:
 *      - On @b iut and @b iut2 run @ref lib-simple_sender (in flood mode)
 *          - @a s: @b iut_s;
 *          - @a size_min: @c 1;
 *          - @a size_max: @c 1000;
 *          - @a size_rnd_once: @b false;
 *          - @a delay_min: @c 0;
 *          - @a delay_max: @c 0;
 *          - @a delay_rnd_once: @b true;
 *          - @a time2run: 10 minutes;
 *      - On @b tst run @ref lib-simple_receiver;
 *          - @a s: @b tst_s.
 * -# Check that sum of sent amount of data is equal to received.
 *    \n @htmlonly &nbsp; @endhtmlonly
 * -# Simultaneously run remote routines with specified below parameters:
 *      - On @b iut run @ref lib-simple_sender (in flood mode)
 *          - @a s: @b iut_s;
 *          - @a size_min: @c 1;
 *          - @a size_max: @c 1000;
 *          - @a size_rnd_once: @b false;
 *          - @a delay_min: @c 0;
 *          - @a delay_max: @c 0;
 *          - @a delay_rnd_once: @b true;
 *          - @a time2run: 10 minutes;
 *      - On @b iut2 run @ref lib-simple_sender (in burst mode)
 *          - @a s: @b iut_s;
 *          - @a size_min: @c 100;
 *          - @a size_max: @c 1000;
 *          - @a size_rnd_once: @b false;
 *          - @a delay_min: @c 0 milliseconds;
 *          - @a delay_max: @c 100 milliseconds;
 *          - @a delay_rnd_once: @b false;
 *          - @a time2run: 10 minutes;
 *      - On @b tst run @ref lib-simple_receiver;
 *          - @a s: @b tst_s.
 * -# Check that sum of sent amount of data is equal to received.
 *    \n @htmlonly &nbsp; @endhtmlonly
 * 
 * @author Andrew Rybchenko <Andrew.Rybchenko@oktetlabs.ru>
 */

#include "sockapi-test.h"
#include "rpc_sendrecv.h"


/* See description in rpc_sendrecv.h */
int 
two_threads_stress(rcf_rpc_server *iut, int iut_s, rpc_socket_domain domain,
                   rcf_rpc_server *tst, int tst_s, const char *method,
                   unsigned int time2run)
{
    rcf_rpc_server        *iut1 = NULL;
    rpc_socket_type        sock_type = RPC_SOCK_STREAM;
    int                    rc = -1;
    int                    sock_child = -1;
    uint64_t               received;
    uint64_t               sent1;
    uint64_t               sent2;
    
    int i;

    tst->def_timeout = iut->def_timeout = time2run * 2000;
    if (strcmp(method, "thread") != 0)
    {
        rpc_create_child_process_socket(method, iut, iut_s, domain, sock_type, 
                                        &iut1, &sock_child);
    }
    else
    {
        if (rcf_rpc_server_thread_create(iut, "IUT_thread", &iut1) != 0)
        {
            ERROR("Failed to create the thread on the IUT");
            return -1;
        }
        sock_child = iut_s;
    }
    
    for (i = 0; i < 2; i++)
    {    
        tst->op = RCF_RPC_CALL;
        rpc_simple_receiver(tst, tst_s, 0, &received);
        iut->op = RCF_RPC_CALL;
        rpc_simple_sender(iut, iut_s, 1, 1000, 0, 0, 0, 1, time2run, 
                          &sent1, 0);
        if (strcmp(method, "inherit_no_net_init") == 0)
            RPC_AWAIT_IUT_ERROR(iut1);
        rpc_simple_sender(iut1, sock_child, 
                          i == 0 ? 1 : 100, 1000, 0, 0, 
                          i == 0 ? 0 : 100, i == 0 ? 1 : 0, 
                          time2run, &sent2, 0);

        rpc_simple_sender(iut, iut_s, 0, 0, 0, 0, 0, 0, 0, &sent1, 0);
        rpc_simple_receiver(tst, tst_s, 0, &received);
        
        if (sent1 + sent2 != received)
        {
            char buf[128];

            sprintf(buf, "Sent data do not match received ones: "
                    "%llu + %llu != %llu (lost %llu)",
                    (unsigned long long)sent1, (unsigned long long)sent2,
                    (unsigned long long)received,
                    (unsigned long long)(sent1 + sent2 - received));
            TEST_FAIL("%s", buf);
        }
    }
        
    rc = 0;
    
    if (rcf_rpc_server_destroy(iut1) < 0)
        ERROR("Failed to destroy thread RPC server on the IUT");
    
    return rc;
}                       
