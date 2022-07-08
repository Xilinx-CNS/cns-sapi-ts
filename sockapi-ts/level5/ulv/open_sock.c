/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/* 
 * User-Level Vulnerabilities testing
 * Corrupt data used during endpoint allocation
 * 
 * $Id$
 */

/** @page level5-ulv-open_sock  Corrupt data used during endpoint allocation
 *
 * @objective Check that corruption of data used during endpoint does not
 *            lead to system crash
 *
 * @param pco_iut       IUT PCO
 * @param pco_tst       Tester PCO
 *
 * @par Scenario
 * -# Create TCP socket @p iut_s of @p pco_iut.
 * -# Listen for the incomming connections on @p iut_s.
 * -# Set free_eps_head to invalid endpoint identifier.
 * -# Connect from @p pco_tst to @p iut_s from two different sockets.
 * -# Accept incoming connections on @p iut_s, try to send/receive data.
 *
 * @author Elena Vengerova <Elena.Vengerova@oktetlabs.ru>
 */

#define TE_TEST_NAME  "ulv/open_sock"

int
main(int argc, char *argv[])
{
    (void)(argc); (void)(argv);
    return 0;
}
