/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/* 
 * User-Level Vulnerabilities testing
 * Corrupt data used for timers management
 * 
 * $Id$
 */

/** @page level5-ulv-bad_timer_state  Corrupt data used for timers management
 *
 * @objective Check that corruption of data used for timers management
 *            does not lead to system crash.
 *
 * @param pco_iut       IUT PCO
 * @param pco_tst       Tester PCO
 * @param field         Field of iptimer_state to be corrupted: "warray" or
 *                      "fire_list".
 * @param fake          Parameter to be passed to @ref level5-ulv-corrupt_dll
 *
 * @par Scenario
 * -# Create TCP and UDP connections between @p pco_iut and @p pco_tst.
 * -# Apply @ref level5-ulv-corrupt_dll to all elements or warray of iptimer_state
 *   or fire_list of iptimer_state (depending of @p field value).
 * -# Send/receive traffic via connections in both directions.
 *
 * @author Elena Vengerova <Elena.Vengerova@oktetlabs.ru>
 */

#define TE_TEST_NAME  "ulv/bad_timer_state"

int
main(int argc, char *argv[])
{
    (void)(argc); (void)(argv);
    return 0;
}
