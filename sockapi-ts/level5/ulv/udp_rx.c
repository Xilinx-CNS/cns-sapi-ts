/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/* 
 * User-Level Vulnerabilities testing
 * Corrupt data used during receiving of UDP packet
 * 
 * $Id$
 */

/** @page level5-ulv-udp_rx  Corrupt data used during receiving of UDP packet
 *
 * @objective Check that corruption of data used during processing
 *            of received UDP packet does not lead to system crash.
 *
 * @param pco_iut       IUT PCO
 * @param pco_tst       Tester PCO
 * @param field         Field of ci_udp_state_s to be corrupted: rx_head
 *                      or rx_tail.
 *
 * @par Scenario
 * -# Create UDP "connection" betweek @p pco_iut and @p pco_tst.
 * -# Find ci_udp_state_s structure corresponding to UDP socket on @p pco_iut.
 * -# Put invalid packet identifier @p field in the structure.
 * -# Increase rx_queue_len of the structure.
 * -# Send UDP packet from @p pco_tst.
 *
 * @author Elena Vengerova <Elena.Vengerova@oktetlabs.ru>
 */

#define TE_TEST_NAME  "ulv/udp_rx"

int
main(int argc, char *argv[])
{
    (void)(argc); (void)(argv);
    return 0;
}
