/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/* 
 * User-Level Vulnerabilities testing
 * Corrupt random data in ci_netif_state
 * 
 * $Id$
 */

/** @page level5-ulv-random  Corrupt random data in ci_netif_state
 *
 * @objective Check that random corruption of the shared memory does not
 *            lead to system crash.
 *
 * @param pco_iut       IUT PCO
 * @param pco_tst       Tester PCO
 *
 * @par Scenario
 * -# Create several stream and datagram connections between @p pco_iut and
 *    @p pco_tst.
 * -# Fill shared state by random data.
 * -# Send data from @p pco_iut via all connections.
 *
 * @author Elena Vengerova <Elena.Vengerova@oktetlabs.ru>
 */

#define TE_TEST_NAME  "ulv/random"

int
main(int argc, char *argv[])
{
    (void)(argc); (void)(argv);
    return 0;
}
