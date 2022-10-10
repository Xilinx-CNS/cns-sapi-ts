/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/*
 * @author Roman Zhukov <Roman.Zhukov@oktetlabs.ru>
 */

#include <stdio.h>
#include <stdbool.h>
#include <errno.h>
#include <string.h>
#include <netdb.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/tcp.h>

#include "ol_helpers.h"
#include "te_hex_diff_dump.h"

static int
ol_bind_port(int sock, int af, int port)
{
    struct sockaddr_storage ss = {0};

    ss.ss_family = af;

    if (af == AF_INET6)
    {
        struct sockaddr_in6 *sa = (struct sockaddr_in6 *)&ss;
        sa->sin6_port = htons((uint16_t) port);
        sa->sin6_addr = in6addr_any;
    }
    else
    {
        struct sockaddr_in *sa = (struct sockaddr_in *)&ss;
        sa->sin_port = htons((uint16_t) port);
        sa->sin_addr.s_addr = htonl(INADDR_ANY);
    }

    return bind(sock, (struct sockaddr *)&ss, sizeof(struct sockaddr));
}

int
ol_enable_tcp_no_delay_opt(int s, const char *app_name)
{
    int enable = 1;

    if (setsockopt(s, SOL_TCP, TCP_NODELAY, &enable, sizeof(enable)) == -1)
    {
        printf("%s: setsockopt(TCP_NODELAY): %s\n", app_name, strerror(errno));
        return -1;
    }

    return 0;
}

static int
ol_getaddrinfo(const char* host, int port, struct addrinfo** ai_out)
{
    char strport[6];

    snprintf(strport, sizeof(strport), "%d", port);

    return getaddrinfo(host, strport, NULL, ai_out);
}

int
ol_connect_socket(int s, ol_connection_type conn_type, int port,
                  const char* host, const char* app_name)
{
    int rc = 0;

    if (conn_type == OL_CONNECT_PASSIVE)
    {
        int acc_s;

        if (ol_bind_port(s, AF_INET, port) < 0)
        {
            printf("%s: bind(): %s\n", app_name, strerror(errno));
            return -1;
        }

        if (listen(s, 1) < 0)
        {
            printf("%s: listen(): %s\n", app_name, strerror(errno));
            return -1;
        }

        printf("%s: waiting for the peer to connect...\n", app_name);

        acc_s = accept(s, NULL, NULL);
        if (acc_s < 0)
        {
            printf("%s: accept(): %s\n", app_name, strerror(errno));
            return -1;
        }

        printf("%s: the peer connected\n", app_name);

        close(s);

        return acc_s;
    }
    else
    {
        int                 max_attempts = 100;
        int                 n_attempts = 0;
        struct addrinfo    *ai;
        struct linger       l;

        if (host == NULL)
        {
            printf("%s: host isn't specified\n", app_name);
            return -1;
        }

        if ((rc = ol_getaddrinfo(host, port, &ai)) != 0)
        {
            printf("%s: getaddrinfo(): %s\n", app_name, gai_strerror(rc));
            return -1;
        }

        if (ai->ai_family != AF_INET)
        {
            printf("%s: getaddrinfo(): %s\n", app_name, gai_strerror(rc));
            return -1;
        }

        l.l_onoff = 1;
        l.l_linger = 1;
        rc = setsockopt(s, SOL_SOCKET, SO_LINGER, &l, sizeof(l));
        if (rc != 0)
        {
            printf("%s: setsockopt(SO_LINGER): %s\n",
                   app_name, strerror(errno));
            return -1;
        }

        while (true)
        {
            rc = connect(s, ai->ai_addr, ai->ai_addrlen);

            if (rc == 0 || ++n_attempts == max_attempts || errno != ECONNREFUSED)
            {
                if (rc != 0)
                {
                    if (errno != ECONNREFUSED)
                    {
                        printf("%s: connect(): %s\n", app_name,
                               strerror(errno));
                    }
                    else
                    {
                        printf("%s: reached maximum number of attempts\n",
                               app_name);
                    }
                }
                break;
            }

            if (n_attempts == 1)
                printf("%s: waiting for the peer to start\n", app_name);

            usleep(100000);
        }

        freeaddrinfo(ai);
        return rc != 0 ? rc : s;
    }

    return -1;
}

int
ol_create_and_connect_socket(ol_connection_type conn_type, int sock_type,
                             int port, const char* host, const char* app_name)
{
    int s = socket(AF_INET, sock_type, 0);

    if (s < 0)
    {
        printf("%s: socket(): %s\n", app_name, strerror(errno));
        return -1;
    }

    return ol_connect_socket(s, conn_type, port, host, app_name);
}

void
ol_hex_diff_dump(const uint8_t  *ex_pkt, const uint8_t *rx_pkt, size_t size)
{
    te_string buf = TE_STRING_INIT;

    te_hex_diff_dump(ex_pkt, size, rx_pkt, size, 0, &buf);
    fputs(buf.ptr, stdout);
    if (buf.len == 0 || buf.ptr[buf.len - 1] != '\n')
        fputc('\n', stdout);

    te_string_free(&buf);
}
