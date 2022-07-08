/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/*
 * Socket API Test Suite
 * /

/** @page usecases-multi_clients_handler Usage of fork() functionality to manage multiple connections
 *
 * @objective Check possibility of handling multiple client connections
 *            at the same time using @b fork().
 *
 * @type conformance
 *
 * @param env       Private set of environments. Create four RPC servers which
 *                  can be located on the same host or different and Onload
 *                  accelerated or not in combinations.
 * @param method    Method of creation new process:
 *                  - Fork-and-exec
 *
 * @par Test sequence:
 * -# Create @p listend socket on @p pco_iut of @c SOCK_STREAM type.
 * -# bind() @p listend socket to address @p iutaddr on @p pco_iut.
 * -# Call @b listen() on @p pco_iut to listen for incoming connections via
 *    @p listend.
 * -# Create @p tst_sock1 socket on @p pco_tst1 of @c SOCK_STREAM type.
 * -# Create @p tst_sock2 socket on @p pco_tst2 of @c SOCK_STREAM type.
 * -# Create @p tst_sock3 socket on @p pco_tst3 of @c SOCK_STREAM type.
 * -# Call @b connect() on @p pco_tst1 to connect the @p tst_sock1 
 *    to @p iutaddr.
 * -# Call @b accept() on socket @p listend on @p pco_iut.
 * -# Get result of @b accept() to create a new connected socket @p a_sockd
 *    on @p pco_iut.
 * -# Call @ref lib-create_child_process_socket on @p pco_iut to create 
 *    @p iut_child1 for processing accepted connection.
 * -# Close accepted socket @p a_sockd on parent pco @p pco_iut.
 * -# In case of unix host, close listening socket @p listend on child pco 
 *    @p iut_child1.
 * -# Call blocking @b accept() on socket @p listend on @p pco_iut.
 * -# Send data on @p pco_tst1 through tst_sock1.
 * -# Receive sent data on @p iut_child1 from connected socket.
 * -# Send received data on @p pco_child1 to @p tst_sock1 on pco_tst1.
 * -# Receive data via @p tst_sock1 on @p pco_tst1.
 * -# Check validity of sent/received data.
 * -# Call blocking @b recv() on @p a_sockd socket on @p iut_child1.
 * -# Send data through @p tst_sock1 on @p pco_tst1 to @p iut_child1.
 * -# Receive sent data on @p iut_child1 from connected socket.
 * -# Check validity of sent/received data.
 * -# Close accepted socket @p a_sockd on @p iut_child1.
 * -# Close connected socket @p tst_sock1 on @p pco_tst1.
 * -# Call @b connect() on @p pco_tst2 to connect to @p iutaddr on @p pco_iut.
 * -# Call @b connect() on @p pco_tst3 to connect to @p iutaddr on @p pco_iut.
 * -# Call @b accept() to create a new connected socket @p a2_sockd;
 *    on @p pco_iut.
 * -# Call @ref lib-create_child_process_socket on @p pco_iut to create 
 *    @p iut_child2 for processing
 *    accepted connection @p a2_sockd.
 * -# Close accepted socket @p a2_sockd on parent pco @p pco_iut.
 * -# In case of unix host, close listening socket @p listend on child pco 
 *    @p iut_child2.
 * -# Send data on @p pco_tst2 through @p tst_sock2.
 * -# Receive sent data on @p iut_child2 from connected socket.
 * -# Send received data on @p pco_child2 to @p tst_sock2 on @p pco_tst2.
 * -# Receive data via @p tst_sock2 on @p pco_tst2.
 * -# Check validity of sent/received data.
 * -# Call @b accept() to create a new connected socket @p a3_sockd;
 * -# Call @ref lib-create_child_process_socket on @p pco_iut to create 
 *    @p iut_child3 for processing
 *    accepted connection @p a3_sockd.
 * -# Close accepted socket @p a3_sockd on parent pco @p pco_iut.
 * -# In case of unix host, close listening socket @p listend on child pco 
 *    @p iut_child3.
 * -# Close listening socket @p listend on @p pco_iut.
 * -# Send data on @p pco_tst3 through @p tst_sock3.
 * -# Receive sent data on @p iut_child3 from connected socket.
 * -# Send received data on @p pco_child3 to @p tst_sock3 on @p pco_tst3.
 * -# Receive data via @p tst_sock3 on @p pco_tst3.
 * -# Check validity of sent/received data.
 * -# Call blocking @b recv() on @p a2_sockd socket on @p iut_child2.
 * -# Send data on @p pco_tst2 through @p tst_sock2.
 * -# Receive sent data on @p iut_child2 from connected socket.
 * -# Check validity of sent/received data.
 * -# Close all socket on all pco.
 * -# Destroy all pco children.
 * 
 * @author Mamadou Ngom <Mamadou.Ngom@oktetlabs.ru>
 */

#define TE_TEST_NAME  "usecases/multi_clients_handler"

#include "sockapi-test.h"



int
main(int argc, char *argv[])
{

    rcf_rpc_server    *pco_iut = NULL;
    rcf_rpc_server    *iut_child1 = NULL;
    rcf_rpc_server    *iut_child2 = NULL;
    rcf_rpc_server    *iut_child3 = NULL;

    rcf_rpc_server    *pco_tst1 = NULL;
    rcf_rpc_server    *pco_tst2 = NULL;
    rcf_rpc_server    *pco_tst3 = NULL;

    const char        *method;

    const struct sockaddr   *iutaddr;

    int listend = -1;
    int a_sockd = -1;
    int a2_sockd = -1;
    int a3_sockd = -1;
    int tst_sock1 = -1;
    int tst_sock2 = -1;
    int tst_sock3 = -1;
    int sock_child1 = -1;
    int sock_child2 = -1;
    int sock_child3 = -1;

    void *rd_buffer = NULL;
    void *wr_buffer = NULL;
    void *buffer = NULL;

    size_t  wr_buflen;
    size_t  rd_buflen;
    size_t  buflen;

    int sent;
    int received;

    rpc_socket_domain domain;

    TEST_START;
    TEST_GET_ADDR(pco_iut, iutaddr);
    TEST_GET_PCO(pco_iut);
    TEST_GET_PCO(pco_tst1);
    TEST_GET_PCO(pco_tst2);
    TEST_GET_PCO(pco_tst3);
    TEST_GET_STRING_PARAM(method);

    if ((wr_buffer = sockts_make_buf_stream(&wr_buflen)) == NULL)
        TEST_FAIL("sockts_make_buf_stream() failed.");

    if ((rd_buffer = te_make_buf_min(wr_buflen, &rd_buflen)) == NULL)
        TEST_FAIL("te_make_buf_min() failed.");

    if ((buffer = te_make_buf_min(wr_buflen, &buflen)) == NULL)
        TEST_FAIL("te_make_buf_min() failed.");

    domain = rpc_socket_domain_by_addr(iutaddr);

    if ((listend = rpc_create_and_bind_socket(pco_iut, RPC_SOCK_STREAM,
                                              RPC_PROTO_DEF, TRUE, FALSE,
                                              iutaddr)) < 0)
        TEST_FAIL("Cannot create SOCK_STREAM 'listend' socket");

    rpc_listen(pco_iut, listend, SOCKTS_BACKLOG_DEF);

    tst_sock1 = rpc_socket(pco_tst1, domain, RPC_SOCK_STREAM, RPC_PROTO_DEF);
    tst_sock2 = rpc_socket(pco_tst2, domain, RPC_SOCK_STREAM, RPC_PROTO_DEF);
    tst_sock3 = rpc_socket(pco_tst3, domain, RPC_SOCK_STREAM, RPC_PROTO_DEF);
    rpc_connect(pco_tst1, tst_sock1, iutaddr);

    a_sockd = rpc_accept(pco_iut, listend, NULL, NULL);

    rpc_create_child_process_socket(method, pco_iut, a_sockd, domain,
                                    RPC_SOCK_STREAM, &iut_child1,
                                    &sock_child1);

    rpc_close(pco_iut, a_sockd);
    rpc_close(iut_child1, listend);

    pco_iut->op = RCF_RPC_CALL;
    a2_sockd = rpc_accept(pco_iut, listend, NULL, NULL);

    RPC_SEND(sent, pco_tst1, tst_sock1, wr_buffer, wr_buflen, 0);

    RPC_AWAIT_IUT_ERROR(iut_child1);
    rc = rpc_recv(iut_child1, sock_child1, rd_buffer, rd_buflen, 0);
    if( rc < 0 )
      TEST_FAIL("Send unexpectedly failed.");

    RPC_SEND(rc, iut_child1, sock_child1, rd_buffer, rc, 0);

    received = rpc_recv(pco_tst1, tst_sock1, buffer, buflen, 0);

    if (sent != received)
        TEST_FAIL("(iut_child1<===>pco_tst1): Only part of sent data \
                  are received.");
    if (memcmp(wr_buffer, buffer, sent))
        TEST_FAIL("(iut_child1<===>pco_tst1): The data received \
                   is invalid.");

    iut_child1->op = RCF_RPC_CALL;
    received = rpc_recv(iut_child1, sock_child1, rd_buffer, rd_buflen, 0);

    RPC_SEND(sent, pco_tst1, tst_sock1, wr_buffer, wr_buflen, 0);

    received = rpc_recv(iut_child1, sock_child1, rd_buffer, rd_buflen, 0);

    if (sent != received)
        TEST_FAIL("(iut_child1<===>pco_tst1): Only part of sent data \
                  are received.");

    if (memcmp(wr_buffer, rd_buffer, sent))
        TEST_FAIL("(iut_child1<===>pco_tst1): The data received is invalid.");

    RPC_CLOSE(iut_child1, sock_child1);
    RPC_CLOSE(pco_tst1, tst_sock1);

    rpc_connect(pco_tst2, tst_sock2, iutaddr);
    TAPI_WAIT_NETWORK;
    rpc_connect(pco_tst3, tst_sock3, iutaddr);

    pco_iut->op = RCF_RPC_WAIT;
    a2_sockd = rpc_accept(pco_iut, listend, NULL, NULL);

    rpc_create_child_process_socket(method, pco_iut, a2_sockd, domain,
                                    RPC_SOCK_STREAM, &iut_child2,
                                    &sock_child2);

    rpc_close(pco_iut, a2_sockd);
    rpc_close(iut_child2, listend);

    RPC_SEND(sent, pco_tst2, tst_sock2, wr_buffer, wr_buflen, 0);

    rc = rpc_recv(iut_child2, sock_child2, rd_buffer, rd_buflen, 0);

    RPC_SEND(rc, iut_child2, sock_child2, rd_buffer, rc, 0);

    received = rpc_recv(pco_tst2, tst_sock2, buffer, buflen, 0);

    if (sent != received)
        TEST_FAIL("(iut_child2<===>pco_tst2): Only part of sent data \
                  are received.");
    if (memcmp(wr_buffer, buffer, sent))
        TEST_FAIL("(iut_child2<===>pco_tst2): The data received \
                   is invalid.");

    a3_sockd = rpc_accept(pco_iut, listend, NULL, NULL);

    rpc_create_child_process_socket(method, pco_iut, a3_sockd, 
                                    domain, RPC_SOCK_STREAM, 
                                    &iut_child3, &sock_child3);

    rpc_close(pco_iut, a3_sockd);
    rpc_close(iut_child3, listend);

    RPC_CLOSE(pco_iut, listend);

    RPC_SEND(sent, pco_tst3, tst_sock3, wr_buffer, wr_buflen, 0);

    rc = rpc_recv(iut_child3, sock_child3, rd_buffer, rd_buflen, 0);

    RPC_SEND(rc, iut_child3, sock_child3, rd_buffer, rc, 0);

    received = rpc_recv(pco_tst3, tst_sock3, buffer, buflen, 0);

    if (sent != received)
        TEST_FAIL("(iut_child3<===>pco_tst3): Only part of sent data \
                  are received.");
    if (memcmp(wr_buffer, buffer, sent))
        TEST_FAIL("(iut_child3<===>pco_tst3): The data received \
                   is invalid.");

    iut_child2->op = RCF_RPC_CALL;
    received = rpc_recv(iut_child2, sock_child2, rd_buffer, rd_buflen, 0);

    RPC_SEND(sent, pco_tst2, tst_sock2, wr_buffer, wr_buflen, 0);

    received = rpc_recv(iut_child2, sock_child2, rd_buffer, rd_buflen, 0);

    if (sent != received)
        TEST_FAIL("(iut_child2<===>pco_tst2): Only part of sent data are \
                  received.");
    if (memcmp(wr_buffer, rd_buffer, sent))
        TEST_FAIL("(iut_child2<===>pco_tst2): The data received \
                   is invalid.");

    TEST_SUCCESS;

cleanup:
    CLEANUP_RPC_CLOSE(pco_tst1, tst_sock1);
    CLEANUP_RPC_CLOSE(pco_tst2, tst_sock2);
    CLEANUP_RPC_CLOSE(pco_tst3, tst_sock3);
    CLEANUP_RPC_CLOSE(pco_iut, listend);

    CLEANUP_RPC_CLOSE(iut_child1, sock_child1);
    CLEANUP_RPC_CLOSE(iut_child2, sock_child2);
    CLEANUP_RPC_CLOSE(iut_child3, sock_child3);

    if (iut_child1 != NULL)
        CLEANUP_CHECK_RC(rcf_rpc_server_destroy(iut_child1));

    if (iut_child2 != NULL)
        CLEANUP_CHECK_RC(rcf_rpc_server_destroy(iut_child2));

    if (iut_child3 != NULL)
        CLEANUP_CHECK_RC(rcf_rpc_server_destroy(iut_child3));

    free(wr_buffer);
    free(rd_buffer);
    free(buffer);
    TEST_END;
}
