/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/* 
 * User-Level Vulnerabilities testing
 * Corrupt fields with packet identifiers
 * 
 * $Id$
 */

/** @page level5-ulv-bad_pktid  Corrupt fields with packet identifiers
 *
 * @objective Check that corruption of fields with packet identifiers
 *            does not lead to system crash.
 *
 * @param pco_iut       IUT PCO
 * @param pco_tst       Tester PCO
 * @param field         Field to corrupt: "dmaq_head", "dmaq_tail", 
 *                      "freepkts" or "nonb_pkt_pool"
 *
 * @par Scenario
 * -# Create TCP connection between @p pco_iut and @p pco_tst.
 * -# Set @p field to random invalid packet identifier.
 * -# Send a lot of data from @p pco_tst.
 *
 * @author Elena Vengerova <Elena.Vengerova@oktetlabs.ru>
 */

#define TE_TEST_NAME  "ulv/bad_pktid"

int
main(int argc, char *argv[])
{
    (void)(argc); (void)(argv);
    return 0;
}
