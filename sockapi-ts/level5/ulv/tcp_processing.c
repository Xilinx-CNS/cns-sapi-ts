/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/* 
 * User-Level Vulnerabilities testing
 * Corrupt data used during TCP cases processing
 * 
 * $Id$
 */

/** @page level5-ulv-tcp_processing  Corrupt data used during TCP cases processing
 *
 * @objective Check that corruption of TCP structures corresponding to
 *            existing connection does not lead to system crash during
 *            traffic and timers processing.
 *
 * @param pco_iut       IUT PCO
 * @param pco_tst       Tester PCO
 * @param field         Data to be corrupted: 
 *                        send;
 *                        retrans;
 *                        recv1;
 *                        recv2;
 *                        rob;
 *                        send_prequeue;
 *                        recv1_extract;
 *                        last_sack;
 *                        dsack_block
 *
 * @param head          If @c TRUE, head of the queue should be corrupted
 *                      (ignored for recv1_extract, last_sack and 
 *                       dsack_block)
 *
 * @par Scenario
 * -# Create a TCP connection between @p pco_iut and @p pco_tst.
 * -# Overfill transmit buffers on @p pco_iut side.
 * -# Find ci_tcp_state_s structure corresponding to connection and
 *    corrupt data as specified in @p field and @p head - place
 *    invalid packet identifier to head/tail of the queue,
 *    recv1_extract, dsack_block or all elements of last_sack.
 * -# Send/receive data via socket on @p pco_tst.
 * -# Close connection on @p pco_tst.
 * -# Exit from the process corresponding to @p pco_iut.
 *
 * @author Elena Vengerova <Elena.Vengerova@oktetlabs.ru>
 */

#define TE_TEST_NAME  "ulv/tcp_processing"

int
main(int argc, char *argv[])
{
    (void)(argc); (void)(argv);
    return 0;
}
