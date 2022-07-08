/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/*
 * Socket API Test Suite
 * UNIX daemons and utilities
 *
 * $Id$
 */

/** @page services-smtp_srv_clnt SMTP server E-mail receiving/relaying
 *
 * @objective Check that SMTP server may receive and relay E-mail.
 *
 * @param pco_iut    IUT PCO
 * @param pco_tst1   tester PCO for the tester SMTP server and SMTP client
 * @param pco_tst2   tester PCO for the SMTP client
 * @param server     SMTP server to be tested (sendmail, postfix, exim4)
 * @param library    transport library to be used on the IUT
 *
 * @note IUT plays role of both SMTP server and client: it receives
 *       the mail from tester client and relays it to the tester server.
 *
 * @note It is assumed that host with @p pco_tst2 is connected with
 * host with IUT via different network segment than one connecting
 * @p pco_iut and @p pco_tst1.
 *
 * @par Scenario
 * -# Set @c LD_PRELOAD environment variable to @p library on the @p pco_iut.
 * -# Configure name resolver on the host @p pco_iut to resolve
 *    mail exchange "tst.tst" to IP address of the host with @p pco_tst1.
 * -# Disable SMTP server on the @p pco_tst1.
 * -# Create IPv4 @c STREAM socket on @p pco_tst1 and bind it to SMTP port.
 * -# Configure SMTP server on the @p pco_iut to relay mail to the @p pco_tst1.
 * -# Create several IPv4 @c STREAM sockets on the @p pco_tst1 and
 *    several sockets on the @p pco_tst2 and connect them to the SMTP port
 *    of the host with @p pco_iut.
 * -# Issue SMTP commands to send mail to "tester@tst.tst" via all connections.
 * -# Close all connections.
 * -# Accept connection(s) from @p pco_iut on the @p pco_srv and receive
 *    all E-mails.
 * -# Repeat the test sequence using @p pco_tst2 as SMTP server instead
 *    @p pco_tst1.
 * -# Unset @c LD_PRELOAD environment variable on the @p pco_iut.
 *
 * @author Elena Vengerova <Elena.Vengerova@oktetlabs.ru>
 */

#define TE_TEST_NAME  "services/smtp_srv_clnt"

#include "sockapi-test.h"
#include "rcf_api.h"
#include "conf_api.h"
#include "tapi_file.h"
#include "tapi_sockaddr.h"
#include "services.h"

static char cmd_buf[1024];       /* Command buffer */
static char ans_buf[2048];       /* Answer buffer */

#define SMTP_DEFAULT_PORT       htons(25)

#define PATTERN                 "Hello, world!"

#define FAKE_HOSTNAME           "myhost"

/** Send E-mail to specified connection */
static int
send_email(rcf_rpc_server *clnt, int s)
{
    int result = 0;
    int len;

/* Send SMTP command to the connection and read an answer */
#define CMD(_cmd...) \
    do {                                                                \
        sprintf(cmd_buf, _cmd);                                         \
        RING("Request: %s", cmd_buf);                                   \
        RPC_WRITE(len, clnt, s, cmd_buf, strlen(cmd_buf));              \
        memset(ans_buf, 0, sizeof(ans_buf));                            \
        len = rpc_read(clnt, s, ans_buf, sizeof(ans_buf));              \
        RING("Response: %s", ans_buf);                                  \
        if (*ans_buf == '\0' || *ans_buf == '4' || *ans_buf == '5')     \
            TEST_FAIL("Invalid answer from SMTP server "                \
                      "(command <%s> answer <%s>", cmd_buf, ans_buf);   \
    } while (0)

    len = rpc_read(clnt, s, ans_buf, sizeof(ans_buf));
    RING("Response: %s", ans_buf);
    CMD("HELO %s\r\n", FAKE_HOSTNAME);
    CMD("MAIL FROM:<client@tester>\r\n");
    CMD("RCPT TO:<server@tester>\r\n");
    CMD("DATA\r\n");
    CMD("Hello, world!\r\n.\r\n");
    CMD("QUIT\r\n");

#undef CMD

    return result;
}

#define SEND_EMAIL(_clnt, _s) \
    if (send_email(_clnt, _s) != 0) \
        TEST_FAIL("Can't send e-mail to SMTP server.")

/**
 * Receive E-mail via established connection.
 *
 * @param srv   RPC server
 * @param s     socket connected to SMTP relay
 * @param num   location for E-mails number
 * @param check if TRUE, check E-mail content
 *
 * @return 0 (success) or -1 (failure)
 */
static int
receive_email(rcf_rpc_server *srv, int s, int *num, te_bool check)
{
    int result = 0;
    int len;

    te_bool mail_from_received = FALSE;
    static const char body_contents[] = PATTERN;
    const char *body_ptr = body_contents;

#define RECV_CMD \
    do {                                                                \
        memset(cmd_buf, 0, sizeof(cmd_buf));                            \
        len = rpc_read(srv, s, cmd_buf, sizeof(cmd_buf));               \
        RING("Request: %s", cmd_buf);                                   \
    } while (0)

#define SEND_ANS(_answer) \
    do {                                                                \
        strcpy(ans_buf, _answer);                                       \
        RING("Response: %s", ans_buf);                                  \
        RPC_WRITE(len, srv, s, ans_buf, strlen(ans_buf));               \
    } while (0)

#define CMD_ANS(_awaited, _answer) \
    do {                                                                \
        RECV_CMD;                                                       \
        if (strncasecmp(_awaited, cmd_buf, strlen(_awaited)) != 0)      \
            TEST_FAIL("Unexpected command: %s", cmd_buf);               \
        SEND_ANS(_answer);                                              \
    } while (0)

    SEND_ANS("220\r\n");
    RECV_CMD;
    if (strncasecmp(cmd_buf, "HELO", strlen("HELO")) != 0 &&
        strncasecmp(cmd_buf, "EHLO", strlen("EHLO")) != 0)
    {
        TEST_FAIL("Unexpected command: %s", cmd_buf);
    }
    SEND_ANS("250\r\n");

    while (TRUE)
    {
        if (!mail_from_received)
            CMD_ANS("MAIL FROM:", "250\r\n");
        mail_from_received = FALSE;

        CMD_ANS("RCPT TO:", "250\r\n");
        CMD_ANS("DATA", "354\r\n");

        body_ptr = body_contents;
        while (TRUE)
        {
            char *tmp;

            RECV_CMD;

            for (tmp = cmd_buf; *tmp != '\0'; tmp++)
            {
                if (body_ptr < body_contents + sizeof(body_contents) - 1)
                {
                    if (*body_ptr == *tmp)
                        body_ptr++;
                    else
                        body_ptr = body_contents;
                }
            }

            tmp = cmd_buf + strlen(cmd_buf) - 1;
            while ((*tmp == '\n' || *tmp == '\r') && tmp > cmd_buf)
                tmp--;

            if (*tmp == '.' || tmp == cmd_buf)
                break;
        }
        SEND_ANS("250\r\n");

        if (check && body_ptr < body_contents + sizeof(body_contents) - 1)
            TEST_FAIL("Data in E-mail body do not contain the pattern");

        *num = *num + 1;

        RECV_CMD;
        if (strncasecmp("QUIT", cmd_buf, strlen("QUIT")) == 0)
        {
            SEND_ANS("221\r\n");
            return 0;
        }
        else if (strncasecmp("RSET", cmd_buf, strlen("RSET")) == 0)
        {
            SEND_ANS("250\r\n");
        }
        else if (strncasecmp("MAIL FROM", cmd_buf, strlen("MAIL FROM")) == 0)
        {
            mail_from_received = TRUE;
            SEND_ANS("250\r\n");
        }
        else
        {
            CLEANUP_RPC_CLOSE(srv, s);
            TEST_FAIL("Unexpected command: \"%s\"", cmd_buf);
        }
     }

#undef RECV_CMD
#undef SEND_ANS
#undef CMD_ANS

    return result;
}

/**
 * Receive all E-mails from the IUT SMTP relay.
 *
 * @param srv   RPC server
 * @param s     socket listening on SMTP port
 * @param num   location for E-mails number
 * @param check if TRUE, check E-mail content
 *
 * @return 0 (success) or -1 (failure)
 */
static int
receive_all_emails(rcf_rpc_server *srv, int s, int *num, te_bool check)
{
    rpc_fd_set_p set = rpc_fd_set_new(srv);
    int          result = 0;
    int          s_acc = -1;

    struct sockaddr_storage from;
    socklen_t               fromlen = sizeof(from);

    if (set == RPC_NULL)
    {
        ERROR("Cannot allocate fd_set on the %s\n", srv->name);
        return -1;
    }

    memset(&from, 0, sizeof(from));
    while (TRUE)
    {
        tarpc_timeval  tv = {10, 0};
        int n;

        rpc_do_fd_zero(srv, set);
        rpc_do_fd_set(srv, s, set);
        n = rpc_select(srv, s + 1, set, RPC_NULL, RPC_NULL, &tv);
        if (n == 0)
            break;

        s_acc = rpc_accept(srv, s, (struct sockaddr *)&from, &fromlen);
        if ((result = receive_email(srv, s_acc, num, check)) != 0)
            break;

        RPC_CLOSE(srv, s_acc);
    }

    if (set != RPC_NULL)
        rpc_fd_set_delete(srv, set);

    CLEANUP_RPC_CLOSE(srv, s_acc);

    return result;
}

int
main(int argc, char *argv[])
{
    rcf_rpc_server *pco_iut = NULL;
    rcf_rpc_server *pco_tst = NULL;
    rcf_rpc_server *pco_tst2 = NULL;

    const struct sockaddr  *iut_addr;
    const struct sockaddr  *iut_addr2;
    const struct sockaddr  *tst_addr;
    const struct sockaddr  *tst2_addr;

    const char       *server;

    const struct sockaddr  *srv_addr;

    rcf_rpc_server *srv = NULL;
    rcf_rpc_server *clnt[4];
    struct servent *entry = NULL;
    uint16_t        smtp_port;

    int s_srv = -1;
    int s_clnt[4] = { -1, -1, -1, -1 };

    int i;

    TEST_START;

    TEST_GET_PCO(pco_iut);
    TEST_GET_PCO(pco_tst);
    TEST_GET_PCO(pco_tst2);
    clnt[0] = clnt[2] = pco_tst;
    clnt[1] = clnt[3] = pco_tst2;
    TEST_GET_ADDR(pco_iut, iut_addr);
    TEST_GET_ADDR(pco_iut, iut_addr2);
    TEST_GET_ADDR(pco_tst, tst_addr);
    TEST_GET_ADDR(pco_tst2, tst2_addr);
    TEST_GET_STRING_PARAM(server);

    TEST_CHECK_SERVICE(pco_iut->ta, smtp);

    /* Disable running SMTP server on the IUT */
    CHECK_RC(cfg_set_instance_fmt(CVT_INTEGER, (void *)0,
                                  "/agent:%s/smtp:", pco_iut->ta));

    /* Specify the daemon to be tested */
    CHECK_RC(cfg_set_instance_fmt(CVT_STRING, server,
                                  "/agent:%s/smtp:/server:", pco_iut->ta));

    /* Create socket for smarthost emulation */
    if ((entry = getservbyname("smtp", NULL)) != NULL)
        smtp_port = entry->s_port;
    else
        smtp_port = SMTP_DEFAULT_PORT;

    te_sockaddr_set_port((struct sockaddr *)tst_addr, smtp_port);
    te_sockaddr_set_port((struct sockaddr *)tst2_addr, smtp_port);
    te_sockaddr_set_port((struct sockaddr *)iut_addr, smtp_port);
    te_sockaddr_set_port((struct sockaddr *)iut_addr2, smtp_port);

    for (srv = pco_tst, srv_addr = tst_addr;
         ;
         srv = pco_tst2, srv_addr = tst2_addr)
    {
        int opt_val = 1;

        TEST_CHECK_SERVICE(srv->ta, smtp);

        /* Disable SMTP server on the tester */
        CHECK_RC(cfg_set_instance_fmt(CVT_INTEGER, (void *)0,
                                      "/agent:%s/smtp:", srv->ta));

        s_srv = rpc_socket(srv, rpc_socket_domain_by_addr(srv_addr),
                           RPC_SOCK_STREAM, RPC_PROTO_DEF);
        rpc_setsockopt(srv, s_srv, RPC_SO_REUSEADDR, &opt_val);
        rpc_bind(srv, s_srv, srv_addr);
        rpc_listen(srv, s_srv, 20);

        /* Specify smarthost */
        CHECK_RC(cfg_set_instance_fmt(CVT_ADDRESS, srv_addr,
                                      "/agent:%s/smtp:/smarthost:",
                                      pco_iut->ta));

        /* Enable SMTP server on the IUT */
        CHECK_RC(cfg_set_instance_fmt(CVT_INTEGER, (void *)1,
                                      "/agent:%s/smtp:", pco_iut->ta));

        /* Receive old E-mails */
        RING("Receive old e-mail to empty the queue");
        if (receive_all_emails(srv, s_srv, &i, FALSE) != 0)
            TEST_STOP;
        RING("Now the queue should be empty");

        /* Create client connections */
        for (i = 0; i < 4; i++)
        {
            s_clnt[i] = rpc_socket(clnt[i],
                                   rpc_socket_domain_by_addr(srv_addr),
                                   RPC_SOCK_STREAM, RPC_PROTO_DEF);
            rpc_connect(clnt[i], s_clnt[i],
                        clnt[i] == pco_tst ? iut_addr : iut_addr2);
        }

        /* Send E-mails */
        for (i = 0; i < 4; i++)
            SEND_EMAIL(clnt[i], s_clnt[i]);

        /* Flush SMTP server's queue */
        CHECK_RC(rcf_ta_call(pco_iut->ta, 0, "flush_smtp_server_queue",
                             &rc, 0, TRUE));

        for (i = 0; i < 4; i++)
            RPC_CLOSE(clnt[i], s_clnt[i]);

        /* Receive E-mails */
        i = 0;
        if (receive_all_emails(srv, s_srv, &i, TRUE) != 0)
            TEST_STOP;

        if (i < 4)
            TEST_FAIL("%d E-mails are not received", 4 - i);

        if (srv == pco_tst2)
            break;

        /* Disable running SMTP server on the IUT */
        CHECK_RC(cfg_set_instance_fmt(CVT_INTEGER, (void *)0,
                                      "/agent:%s/smtp:", pco_iut->ta));

        RPC_CLOSE(srv, s_srv);
    }

    TEST_SUCCESS;

cleanup:
    /* Remove me! */
    rpc_system(pco_iut, "cat /etc/hosts");

    CLEANUP_RPC_CLOSE(srv, s_srv);
    for (i = 0; i < 4; i++)
        CLEANUP_RPC_CLOSE(clnt[i], s_clnt[i]);

    TEST_END;
}

