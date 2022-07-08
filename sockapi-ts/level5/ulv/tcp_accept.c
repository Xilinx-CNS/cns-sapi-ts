/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/* 
 * User-Level Vulnerabilities testing
 * Corrupt data used during processing of incoming TCP connection
 * 
 * $Id$
 */

/** @page level5-ulv-tcp_accept  Corrupt data used during processing of incoming TCP connection
 *
 * @objective Check that corruption of data used during processing of
 *            incoming TCP connections does not lead to system crash.
 *
 * @param pco_iut       IUT PCO
 * @param pco_tst       Tester PCO
 * @param field         Data to be corrupted: listenq_free, acceptq,
 *                      listenq_list, epcache_cache or epcache_pending.
 * @param fake          Parameter to be passed to @ref level5-ulv-corrupt_dll
 *
 * @par Scenario
 * -# Create listening TCP socket on @p pco_iut.
 * -# Create 2 connections from @p pco_tst; close one of them.
 * -# If @p field is equal to "listenq_free", apply @ref level5-ulv-corrupt_dll
 *    to listenq_free.
 * -# Otherwise find ci_tcp_socket_listen structure @p tsl corresponding to
 *    listening socket. 
 * -# If @p field is "acceptq" or "epcache_pending" or "epcache_cache" 
 *    apply @ref level5-ulv-corrupt_dll to @p field of @p tsl.
 * -# If @p field is "epcache_pending" or "epcache_cache", exit from
 *    the process corresponding to @p pco_iut (forcing relasing of 
 *    list elements from the kernel) and finish the test.
 * -# Send two TCP SYN from tester.
 * -# If @p field is "listenq_list" apply @ref level5-ulv-corrupt_dll to 
 *    listenq_list field of @p tsl.
 * -# If SYN ACK is received from @p pco_iut, send ACK from @p pco_tst.
 *
 * @author Elena Vengerova <Elena.Vengerova@oktetlabs.ru>
 */

#define TE_TEST_NAME  "ulv/tcp_accept"

int
main(int argc, char *argv[])
{
    (void)(argc); (void)(argv);
    return 0;
}
