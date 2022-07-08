/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/* 
 * User-Level Vulnerabilities testing
 * Corrupt data used for packets reassembling
 * 
 * $Id$
 */

/** @page level5-ulv-defrag  Corrupt data used for packets reassembling
 *
 * @objective Check that corruption of data used for packet reassembling
 *            does not lead to system crash.
 *
 * @param pco_iut       IUT PCO
 * @param pco_tst       Tester PCO
 *
 * @par Scenario
 * -# Create socket on @p pco_iut and bind it to wildcard address and
 *    port @p P.
 * -# Set rx_defrag_head and rx_defrag_tail to random invalid packet
 *    identifier.
 * -# Send fragmented UDP datagram with destination port @p P to @p pco_iut 
 *    from @p pco_tst.
 *
 * @author Elena Vengerova <Elena.Vengerova@oktetlabs.ru>
 */

#define TE_TEST_NAME  "ulv/defrag"

int
main(int argc, char *argv[])
{
    (void)(argc); (void)(argv);
    return 0;
}
