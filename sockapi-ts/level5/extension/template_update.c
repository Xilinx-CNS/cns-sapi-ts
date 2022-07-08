/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/* 
 * Socket API Test Suite
 * Onload extensions
 *
 * $Id$
 */

/** @page extension-template_update Test updating templates
 *
 * @objective Check that onload_msg_template_update changes allocated
 *            templates as expected.
 *
 * @param pco_iut       PCO on IUT
 * @param pco_tst       PCO on TST
 * @param iovcnt        IOVs array length
 * @param total         Total amount of data to be passed
 * @param updates_num   Updates number
 * @param mode          Determines way how to perform updates
 * 
 * @type Conformance.
 *
 * @par Scenario:
 *
 * @author Andrey Dmitrov <Andrey.Dmitrov@oktetlabs.ru>
 */

#define TE_TEST_NAME  "level5/extension/template_update"

#include "sockapi-test.h"
#include "template.h"

/**
 * Possible ways to update template
 */
typedef enum {
    UM_SINGLE = 0,      /**< Use template_update once to apply few updates */
    UM_FEW,             /**< Use template_update a few times */
    UM_SINGLE_SEND,     /**< Use template_update once to apply apdate and
                             send the packet in the same call */
} update_mode_type;

#define UPDATE_MODE  \
    { "single", UM_SINGLE },            \
    { "few", UM_FEW },                  \
    { "single_send", UM_SINGLE_SEND }

/**
 * Clean updates array
 * 
 * @param update        Array with updates
 * @param updates_num   Length of the updates array
 */
static void
release_updates(rpc_onload_template_msg_update_iovec *update,
                int updates_num)
{
    int i;

    if (update == NULL)
        return;

    for (i = 0; i < updates_num; i++)
        free(update[i].otmu_base);

    free(update);
}

/**
 * Perform templates update
 * 
 * @param pco_iut       IUT RPC server
 * @param iut_s         Socket
 * @param handle        Onload templates handler
 * @param updates_num   Updates number
 * @param mdoe          Determines way how to update
 * @param sndbuf        Outgoing payload
 * @param total         Total payload length
 */
static rpc_onload_template_msg_update_iovec *
update_template(rcf_rpc_server *pco_iut, int iut_s,
                rpc_onload_template_handle handle, int updates_num,
                update_mode_type mode, char *sndbuf, int total)
{
    int i;
    rpc_onload_template_msg_update_iovec *update;

    update = te_calloc_fill(updates_num, sizeof(*update), 0);

    for (i = 0; i < updates_num; i++)
    {
        update[i].otmu_offset = rand_range(0, total - 1);
        update[i].otmu_len = rand_range(1, total- update[i].otmu_offset);
        update[i].otmu_base = te_make_buf_by_len(update[i].otmu_len);
        memcpy(sndbuf + update[i].otmu_offset, update[i].otmu_base,
               update[i].otmu_len);

        if (mode == UM_FEW)
            rpc_onload_msg_template_update(pco_iut, iut_s, handle,
                                           update + i, 1, 0);
    }

    if (mode == UM_SINGLE || mode == UM_SINGLE_SEND)
        rpc_onload_msg_template_update(pco_iut, iut_s, handle,
                                       update, updates_num,
                                       mode == UM_SINGLE_SEND ?
                                       RPC_ONLOAD_TEMPLATE_FLAGS_SEND_NOW :
                                       0);

    return update;
}

int
main(int argc, char *argv[])
{
    rcf_rpc_server        *pco_iut = NULL;
    rcf_rpc_server        *pco_tst = NULL;
    const struct sockaddr *iut_addr = NULL;
    const struct sockaddr *tst_addr = NULL;
    update_mode_type       mode;

    int iovcnt;
    int updates_num;

    rpc_iovec *iov    = NULL;
    char      *sndbuf = NULL;
    char      *rcvbuf = NULL;
    int        iut_s  = -1;
    int        tst_s  = -1;
    int        total;

    rpc_onload_template_msg_update_iovec *update = NULL;
    rpc_onload_template_handle handle = 0;

    TEST_START;
    TEST_GET_PCO(pco_iut);
    TEST_GET_PCO(pco_tst);
    TEST_GET_ADDR(pco_iut, iut_addr);
    TEST_GET_ADDR(pco_tst, tst_addr);
    TEST_GET_INT_PARAM(iovcnt);
    TEST_GET_INT_PARAM(total);
    TEST_GET_INT_PARAM(updates_num);
    TEST_GET_ENUM_PARAM(mode, UPDATE_MODE);

    sockts_kill_zombie_stacks(pco_iut);

    TEST_STEP("Create TCP connection between IUT and tester.");
    GEN_CONNECTION(pco_iut, pco_tst, RPC_SOCK_STREAM, RPC_PROTO_DEF,
                   iut_addr, tst_addr, &iut_s, &tst_s);

    TEST_STEP("Initialize a number @p iovcnt vectors with total payload length "
              "@p total.");
    iov = init_iovec(iovcnt, total, &sndbuf);

    RING("Total iovec payload size %d", total);

    TEST_STEP("Allocate template.");
    RPC_AWAIT_IUT_ERROR(pco_iut);
    rc = rpc_onload_msg_template_alloc(pco_iut, iut_s, iov, iovcnt,
                                       &handle, 0);
    if (rc != 0)
    {
        TEST_STEP("Allocation fails with E2BIG if try to allocate too big vector");
        if (RPC_ERRNO(pco_iut) == RPC_E2BIG)
            TEST_VERDICT("Template allocation failed with errno %s",
                         errno_rpc2str(RPC_ERRNO(pco_iut)));
        TEST_VERDICT("Template allocation failed with unexpected errno %s",
                     errno_rpc2str(RPC_ERRNO(pco_iut)));
    }

    TEST_STEP("Update template. Call template_update a few times if @p mode is "
              "@c UM_FEW, else create template updates array and pass it once.");
    update = update_template(pco_iut, iut_s, handle, updates_num,
                             mode, sndbuf, total);

    TEST_STEP("Send the updated packet. If @p mode is @c UM_SINGLE_SEND the packet "
              "sent simultaneously with updating.");
    if (mode != UM_SINGLE_SEND)
        rpc_onload_msg_template_update(pco_iut, iut_s, handle, NULL, 0,
                                       RPC_ONLOAD_TEMPLATE_FLAGS_SEND_NOW);

    TEST_STEP("Receive packet on IUT.");
    rcvbuf = te_calloc_fill(2, total, 0);
    if (rpc_recv(pco_tst, tst_s, rcvbuf, total * 2, 0) != total)
        TEST_VERDICT("Amount of received data is not equal to sent data");

    TEST_STEP("Verify obtained data.");
    if (memcmp(rcvbuf, sndbuf, total) != 0)
        TEST_VERDICT("Send and received data are not equal");

    TEST_SUCCESS;

cleanup:
    CLEANUP_RPC_CLOSE(pco_iut, iut_s);
    CLEANUP_RPC_CLOSE(pco_tst, tst_s);

    release_iovec(iov, iovcnt);
    release_updates(update, updates_num);

    free(sndbuf);
    free(rcvbuf);

    TEST_END;
}
