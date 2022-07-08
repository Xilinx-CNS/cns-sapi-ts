/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/*
 * @author Sergey Nikitin <Sergey.Nikitin@oktetlabs.ru>
 */

#ifndef __OL_POLL_H__
#define __OL_POLL_H__

#define OL_POLL_RC_OK   0
#define OL_POLL_RC_FAIL -1
#define OL_POLL_RC_STOP 1

/**
 * User callback function type
 *
 * @param fd            Descriptor on which an event occurs.
 * @param user_data     Pointer to user data.
 *
 * @return Status code
 * @retval OL_POLL_RC_OK    Everything is OK
 * @retval OL_POLL_RC_FAIL  Error occured
 * @retval OL_POLL_RC_STOP  No errors occured, polling has to be stopped.
 */
typedef int (*ol_poll_callback)(int fd, void *user_data);

/**
 * Add a descriptor to poll set.
 *
 * @param fd                The descriptor
 * @param pollin_callback   Callback function which is called on POLLIN event.
 *                          If @c NULL, the event is not handled.
 * @param pollout_callback  Callback function which is called on POLLOUT event.
 *                          If @c NULL, the event is not handled.
 */
void
ol_poll_addfd(int fd, ol_poll_callback pollin_callback,
              ol_poll_callback pollout_callback);

/**
 * Process poll() call. Callback functions are called if an event occurs.
 *
 * @param user_data  User data passed to a callback.
 *
 * @return Status code
 * @retval OL_POLL_RC_OK    Everything is OK
 * @retval OL_POLL_RC_FAIL  Error occured
 * @retval OL_POLL_RC_STOP  No errors occured, polling has to be stopped.
 */
int
ol_poll_process(void *user_data);

#endif /* __OL_POLL_H__ */
