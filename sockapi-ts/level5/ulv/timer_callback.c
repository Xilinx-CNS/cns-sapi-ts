/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/* 
 * User-Level Vulnerabilities testing
 * Corrupt callback number/parameter in timer state
 * 
 * $Id$
 */

/** @page level5-ulv-timer_callback  Corrupt callback number/parameter in timer state
 *
 * @objective Check that corruption of the timer state does not lead to
 *            system crash.
 *
 * @param pco_iut       IUT PCO
 * @param pco_tst       Tester PCO
 * @param callback      If @c TRUE, incorrect callback number should
 *                      be specified; otherwise incorrect endpoint
 *                      identifier should be specified.
 *
 * @par Scenario
 * -# Create listening TCP socket on @p pco_iut.
 * -# Send TCP SYN from @p pco_tst.
 * -# File ci_ip_timer structure corresponding to SYN ACK retransmission
 *    timer in iptimer_state.warray: either assign fn to 
 *    0xE (if callback is @c TRUE) or assign param1 to invalid endpoint
 *    identifier.
 * -# Wait CI_TCP_TCONST_LISTEN_TIME milliseconds.
 *
 * @author Elena Vengerova <Elena.Vengerova@oktetlabs.ru>
 */

#define TE_TEST_NAME  "ulv/timer_callback"

int
main(int argc, char *argv[])
{
    (void)(argc); (void)(argv);
    return 0;
}
