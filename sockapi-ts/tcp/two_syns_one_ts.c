/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/*
 * Socket API Test Suite
 * TCP
 */

/** @page tcp-two_syns_one_ts Receiving two SYNs (SYN-ACKs) with timestamp set in only one of them
 *
 * @objective  Check what happens if two SYN (SYN-ACK) packets are received for the
 *             same connection, and only one of them has TCP timestamp.
 *
 * @type conformance
 *
 * @param env       Testing environment:
 *                  - @ref arg_types_env_peer2peer_gw
 * @param active    If @c TRUE, connection should be initiated
 *                  from IUT, otherwise - from Tester.
 * @param first_ts  If @c TRUE, TCP timestamp should be set in
 *                  the first SYN (SYN-ACK) sent from Tester;
 *                  otherwise it should be sent in the second one.
 *
 * @par Scenario:
 * -# Create TCP socket on IUT, and CSAP TCP socket emulation on Tester.
 * -# If @p active, call connect on IUT socket. Otherwise make it listener.
 * -# Send the first SYN-ACK (SYN) packet from Tester, setting TCP
 *    timestamp in it if @p first_ts is @c TRUE.
 * -# Check that IUT responds with ACK (SYN-ACK) in which TCP timestamp
 *    is set only if it was set in a packet sent from Tester.
 * -# Send the second SYN (SYN-ACK) packet from Tester, setting TCP
 *    timestamp in it if @p first_ts is @c FALSE.
 * -# Check what IUT sends in response, and whether TCP timestamp is set in
 *    it or not.
 * -# Try to send some data in both directions over established connection.
 */

#define TE_TEST_NAME  "tcp/two_syns_one_ts"

int
main(int argc, char *argv[])
{
    TEST_START;

    TEST_SUCCESS;

cleanup:

    TEST_END;
}
