/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/* 
 * User-Level Vulnerabilities testing
 * Corrupt fields used duging IP identifier generation
 * 
 * $Id$
 */

/** @page level5-ulv-bad_ipid  Corrupt fields used duging IP identifier generation
 *
 * @objective Check that corruption of data used during calculation of
 *            IP datagram identifier during IP packet sending does not
 *            lead to system crash.
 *
 * @param pco_iut       IUT PCO
 * @param pco_tst       Tester PCO
 *
 * @par Scenario
 * -# Create TCP connection between @p pco_iut and @p pco_tst.
 * -# Set ipid.current_index and ipid.max_index to value N so that
 *    range[N] points out of the shared state.
 * -# Send data via TCP connection from @p pco_tst to force @p pco_iut
 *    host send IP packet with TCP ACK.
 *
 * @author Elena Vengerova <Elena.Vengerova@oktetlabs.ru>
 */

#define TE_TEST_NAME  "ulv/bad_ipid"

int
main(int argc, char *argv[])
{
    (void)(argc); (void)(argv);
    return 0;
}
