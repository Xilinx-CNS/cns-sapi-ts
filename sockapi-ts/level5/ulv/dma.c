/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/* 
 * User-Level Vulnerabilities testing
 * Corrupt data used to serve DMA queues
 * 
 * $Id$
 */

/** @page level5-ulv-dma  Corrupt data used to serve DMA queues
 *
 * @objective Check that corruption of DMA-related data does not lead
 *            to system crash or incorrect behaivour of the network adapter.
 *
 * @param pco_iut       IUT PCO
 * @param pco_tst       Tester PCO
 * @param field         Corruption scenario:
 *                        rx_dma_credits_small;
 *                        rx_dma_credits_big;
 *                        tx_dma_credits_small;
 *                        tx_dma_credits_big;
 *                        dma_tx_q_mask;
 *                        dma_rx_q_mask;
 *                        rx_ids_mask;
 *                        tx_ids_mask;
 *                        rx_fifo;
 *                        tx_fifo;
 *                        io_mmap
 *
 * @par Scenario
 * -# Create several connections of different types between @p pco_iut and
 *    @p pco_tst.
 *
 * -# If @p field is "X_dma_credits_Y", set p.X_dma_credits in
 *    ef_vi_state_s structure located immediately after ci_netif_state_s
 *    structure in shared memory to 0 (if Y is "small") or 0xFFFFFF (if
 *    Y is "big").
 *
 * -# If @p field is "X_mask", set X.fifo_mask to 0xFFFFFFFF and set
 *    the rest of structure X (except fifo) to random values.
 *
 * -# if @p field is "X_fifo", set array X_ids.fifo to random values.
 *
 * -# If @p field is "io_mmap", corrupt shared memory starting from 
 *    ni->tcp_helper.io_ptr + CI_PAGE_SIZE.
 *
 * -# Send/receive traffic from the @p pco_tst via existing connections. 
 * -# Close TCP connections: one from @p pco_tst, other one from @p pco_iut.
 * -# Close UDP sockets.
 *
 * @author Elena Vengerova <Elena.Vengerova@oktetlabs.ru>
 */

#define TE_TEST_NAME  "ulv/dma"

int
main(int argc, char *argv[])
{
    (void)(argc); (void)(argv);
    return 0;
}
