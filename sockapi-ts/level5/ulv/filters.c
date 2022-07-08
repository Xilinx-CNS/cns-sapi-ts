/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/* 
 * User-Level Vulnerabilities testing
 * Corrupt filters-related data
 * 
 * $Id$
 */

/** @page level5-ulv-filters  Corrupt filters-related data
 *
 * @objective Check that corruption of data used for filters management
 *            does not lead to system crash.
 *
 * @param pco_iut       IUT PCO
 * @param pco_tst       Tester PCO
 * @param field         Corruption scenario: table_size_mask_small,
 *                      tabld_size_mask_big or entry_id
 *
 * @par Scenario
 * -# Create several connections between @p pco_iut and @p pco_tst and
 *    listening TCP socket.
 * -# If @p field is "entry_id", find ci_netif_filter_table_entry structure
 *    corresponding to connections and set id field to invalid endpoint
 *    identifier.
 * -# If @p field is "table_size_mask_X", decrease(if X is "small") or
 *    increase (if X is "big") table_size_mask of ci_netif_filter_table
 *    structure.
 * -# Send/receive traffic from the @p pco_tst via existing connections. 
 * -# Close TCP connections: one from @p pco_tst, other one from @p pco_iut.
 * -# Close UDP sockets.
 * -# Connect to listening socket from @p pco_tst.
 * -# Send/receive traffic from the @p pco_tst via existing connections. 
 * -# Try to create UDP connection.
 * -# Send/receive traffic from the @p pco_tst via existing connections. 
 *
 * @author Elena Vengerova <Elena.Vengerova@oktetlabs.ru>
 */

#define TE_TEST_NAME  "ulv/filters"

int
main(int argc, char *argv[])
{
    (void)(argc); (void)(argv);
    return 0;
}
