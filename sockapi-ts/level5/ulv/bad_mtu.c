/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/* 
 * User-Level Vulnerabilities testing
 * Corrupt min_mtu in ci_netif_state
 * 
 * $Id$
 */

/** @page level5-ulv-bad_mtu  Corrupt min_mtu in ci_netif_state
 *
 * @objective Check that corrupting of min_mtu stored in ci_netif_state
 *            does not lead to system crash during traffic sending.
 *
 * @param pco_iut       IUT PCO
 * @param pco_tst       Tester PCO
 *
 * @par Scenario
 * -# Create stream connection between @p pco_iut and @p pco_tst.
 * -# Overfill transmit buffers on @p pco_iut side.
 * -# Set min_mtu to CI_PAGE_SIZE * 2.
 * -# Block on sending data bulk with length between CI_PAGE_SIZE and 
 *    CI_PAGE_SIZE * 3.
 * -# Receive data on @p pco_tst (provoking sending the bulk from
 *    kernel context).
 *
 * @author Elena Vengerova <Elena.Vengerova@oktetlabs.ru>
 */

#define TE_TEST_NAME  "ulv/bad_mtu"

int
main(int argc, char *argv[])
{
    (void)(argc); (void)(argv);
    return 0;
}
