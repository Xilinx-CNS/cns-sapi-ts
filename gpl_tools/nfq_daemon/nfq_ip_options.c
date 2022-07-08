/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/**
 * Socket API Test Suite
 *
 * Program to mangle packets from NFQUEUE queue 0
 *
 * @author Vasilij Ivanov <Vasilij.Ivanov@oktetlabs.ru>
 */
#include <asm/types.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdint.h>
#include <string.h>
#include <poll.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <sys/socket.h>
#include <linux/netlink.h>
#include <linux/types.h>
#include <linux/netfilter.h>
#include <linux/if_link.h>
#include <linux/rtnetlink.h>
#include <libnetfilter_queue/libnetfilter_queue.h>
#include <libnetfilter_queue/pktbuff.h>
#include <libnetfilter_queue/libnetfilter_queue_ipv4.h>
#include <libnetfilter_queue/libnetfilter_queue_tcp.h>
#include <libnetfilter_queue/libnetfilter_queue_udp.h>

/**
 * We need a buffer to fit a huge IP packet into it.
 * The packet's size is not limited by MTU because of TCP Segmentation Offload
 * and UDP Fragmentation Offload.
 */
#define MAX_PACKET_SIZE 0x80000

/** Maximum length of an IP datagram sent over an Ethernet is 1500 octets. */
#define DEFAULT_ETH_MTU 1500

/** Length of IP options to add. */
#define IP_OPTIONS_LEN 4

#define MAX_PID_LENGTH 10

void
print_log(int ret, const char *log_message, bool standart_log,
          const char *func, int line,
          const char *format, ...)
{
    int     log_fd;
    char    log_buf[512];
    va_list args;

    log_fd = open("/dev/kmsg", O_WRONLY);

    if (log_message != NULL)
    {
        write(log_fd, log_message, strlen(log_message));
    }
    else
    {
        if (standart_log)
        {
            snprintf(log_buf, sizeof(log_buf), "nfq_daemon: "
                     "failed in function %s on line %d "
                     "with code: %d and errno: %s\n",
                     func, line, ret, strerror(errno));
        }
        else
        {
            va_start(args, format);
            vsnprintf(log_buf, sizeof(log_buf), format, args);
        }

        write(log_fd, log_buf, strlen(log_buf));
    }

    close(log_fd);
}

#define PRINT_LOG(ret, log_message, standart_log, format, ...) \
        print_log(ret, log_message, standart_log,              \
                  __func__, __LINE__, format, ##__VA_ARGS__)


typedef struct if_mtu_list {
    int ifi_index;
    int mtu;
    struct if_mtu_list *next;
} if_mtu_list;

if_mtu_list *head;
if_mtu_list *last_used;

if_mtu_list* if_mtu_list_init(int ifi_index)
{
    head = (if_mtu_list *)malloc(sizeof(if_mtu_list));
    head->ifi_index = ifi_index;
    head->mtu = DEFAULT_ETH_MTU;
    head->next = NULL;
    last_used = head;

    return head;
}

if_mtu_list* if_mtu_list_add(int ifi_index, int mtu)
{
    if_mtu_list *current_head = head;
    if_mtu_list *new_head = NULL;

    if (current_head == NULL)
        return if_mtu_list_init(ifi_index);

    new_head = (if_mtu_list *) malloc(sizeof(if_mtu_list));

    new_head->ifi_index = ifi_index;
    if (mtu != -1)
    {
        new_head->mtu = mtu;
    }
    else
    {
        new_head->mtu = DEFAULT_ETH_MTU;
    }
    new_head->next = current_head;

    head = new_head;

    return new_head;
}

if_mtu_list* if_mtu_list_find(int ifi_index)
{
    if_mtu_list *current = head;
    if_mtu_list *finded = NULL;

    if (last_used != NULL && last_used->ifi_index == ifi_index)
        return last_used;

    while (current != NULL)
    {
        if (current->ifi_index == ifi_index)
        {
            finded = current;
            break;
        }
        current = current->next;
    }

    return finded;
}

void
process_netlink_message(char *buf, int answer_size, if_mtu_list *if_mtu_list_entry)
{
    struct nlmsghdr     *nl_msg_ptr;
    struct ifinfomsg    *inf_msg_ptr;
    struct rtattr       *rta_ptr;
    int                  attr_len;
    int                  tmp_len;
    int                  mtu;
    int                  old_mtu;

    for (nl_msg_ptr = (struct nlmsghdr *)buf;
         answer_size > (int)sizeof(*nl_msg_ptr);)
    {
        tmp_len = nl_msg_ptr->nlmsg_len;

        if (nl_msg_ptr->nlmsg_type == NLMSG_ERROR)
        {
            PRINT_LOG(0, NULL, true, NULL);
            return;
        }
        if (!NLMSG_OK(nl_msg_ptr, (unsigned int)answer_size) ||
            (nl_msg_ptr->nlmsg_type == NLMSG_DONE))
        {
            return;
        }

        inf_msg_ptr = (struct ifinfomsg *)NLMSG_DATA(nl_msg_ptr);
        rta_ptr = (struct rtattr *)IFLA_RTA(inf_msg_ptr);

        attr_len = IFLA_PAYLOAD(nl_msg_ptr);

        for (; RTA_OK(rta_ptr, attr_len); rta_ptr = RTA_NEXT(rta_ptr, attr_len))
        {
            if (rta_ptr->rta_type == IFLA_MTU)
            {
                if (if_mtu_list_entry == NULL)
                    if_mtu_list_entry = if_mtu_list_find(inf_msg_ptr->ifi_index);

                if (if_mtu_list_entry == NULL)
                    continue;

                if (if_mtu_list_entry->ifi_index == inf_msg_ptr->ifi_index)
                {
                    memcpy(&mtu, RTA_DATA(rta_ptr), 4);

                    old_mtu = if_mtu_list_entry->mtu;

                    if (mtu != old_mtu)
                    {
                        if_mtu_list_entry->mtu = mtu;
                        PRINT_LOG(0, NULL, false, "nfq_daemon: [interface %d] MTU changed "
                                  "from %d to %d\n",
                                  if_mtu_list_entry->ifi_index,
                                  old_mtu, mtu);
                    }
                }
            }
        }

        answer_size -= NLMSG_ALIGN(tmp_len);
        nl_msg_ptr = (struct nlmsghdr *)((char *)nl_msg_ptr + NLMSG_ALIGN(tmp_len));
    }
}

void
set_starting_mtu(if_mtu_list *if_mtu_list_entry)
{
    struct {
        struct nlmsghdr nl_msg;
        struct ifinfomsg if_inform_msg;
    } standart_request;

    int     sock;
    int     rv;
    char    buf[4096];

    memset(&standart_request, 0, sizeof(standart_request));

    if ((sock = socket(PF_NETLINK, SOCK_DGRAM, NETLINK_ROUTE)) < 0)
    {
        PRINT_LOG(sock, NULL, true, NULL);
        exit(EXIT_FAILURE);
    }

    standart_request.nl_msg.nlmsg_len =
                     NLMSG_LENGTH(sizeof(struct ifinfomsg));
    standart_request.nl_msg.nlmsg_flags = NLM_F_REQUEST | NLM_F_MATCH;
    standart_request.nl_msg.nlmsg_type = RTM_GETLINK;
    standart_request.nl_msg.nlmsg_seq = 1;

    standart_request.if_inform_msg.ifi_index = if_mtu_list_entry->ifi_index;
    standart_request.if_inform_msg.ifi_family = AF_UNSPEC;
    standart_request.if_inform_msg.ifi_change = 0xffffffff;

    if ((rv = send(sock, &standart_request,
           standart_request.nl_msg.nlmsg_len, 0)) < 0)
    {
        PRINT_LOG(rv, NULL, true, NULL);
        exit(EXIT_FAILURE);
    }

    if ((rv = recv(sock, buf, sizeof(buf), 0)) < 0)
    {
        PRINT_LOG(rv, NULL, true, NULL);
        exit(EXIT_FAILURE);
    }
    else
    {
        process_netlink_message(buf, rv, if_mtu_list_entry);
    }

    close(sock);
}

if_mtu_list* if_mtu_list_real_add(int ifi_index)
{
    if_mtu_list* added = if_mtu_list_add(ifi_index, -1);

    set_starting_mtu(added);

    return added;
}

/**
 * Macros to check errno return value.
 *
 * @param ret    Status code
 *
 */
#define CHECK_ERRNO_RET(ret) \
    do {                                                                   \
        int ret_val = ret;                                                 \
        if (ret_val != 0)                                                  \
        {                                                                  \
            PRINT_LOG(ret_val, NULL, true, NULL);                          \
            exit(EXIT_FAILURE);                                            \
        }                                                                  \
    } while (0)

#define add_ip_options(ip_hdr, packet_iterator, fin) \
    do {                                                                \
        bytes_insert(packet_iterator, fin);                             \
        ip_hdr->ihl++;                                                  \
        ip_hdr->tot_len = htons(ntohs(ip_hdr->tot_len) + 4);            \
        nfq_ip_set_checksum(ip_hdr);                                    \
    } while (0)

/*
 * NFQUEUE handler
 */
struct nfq_handle    *nfqueue_handle;
struct nfq_q_handle  *qh;

/**
 * Insert 4 IP options (NOP NOP NOP EOP) after @p fin
 *
 * @param packet_iterator         Pointer to end of the packet
 *                                after inserting bytes
 *
 * @param fin                     Pointer to end of IP header
 */
void
bytes_insert(uint8_t *packet_iterator, uint8_t *fin)
{
    const char nop = 1;
    const char eop = 0;
    uint8_t    bytes_counter = 0;

    for (; packet_iterator >= fin; packet_iterator--)
         *packet_iterator = *(packet_iterator - 4);

    *packet_iterator = eop;
    packet_iterator--;

    for(; bytes_counter < 3; bytes_counter++)
    {
        *packet_iterator = nop;
        packet_iterator--;
    }
}

/**
 * Callback function which adds 4 IP options (NOP NOP NOP EOP)
 * to every TCP/UDP packet which were sent to her.
 * Other packets would not be changed.
 *
 * @param qh             Pointer to nfqueue queue handler
 * @param nfa            Pointer to data from nfqueue
 * @param nfmsg          Unused variable
 * @param data           Unused variable
 *
 * @return               Verdict on a packet
 */
static int
packet_mangling(struct nfq_q_handle *qh, struct nfgenmsg *nfmsg,
                struct nfq_data *nfa, void *data)
{
    struct nfqnl_msg_packet_hdr *ph = NULL;
    uint32_t            id = 0;

    uint8_t            *pkt_data = NULL;
    struct iphdr       *ip_hdr = NULL;
    void               *hdr = NULL;
    uint8_t             ip_proto;
    uint8_t            *packet_iterator = NULL;
    uint8_t            *fin = NULL;
    int                 len = nfq_get_payload(nfa, &pkt_data);
    struct pkt_buff    *pkBuff = pktb_alloc(AF_INET, pkt_data, len, 4);
    int                 rc = 0;
    /* outdev - real interface where packet would be passed */
    uint32_t            ifi_index = nfq_get_outdev(nfa);
    struct if_mtu_list *if_mtu_list_entry = if_mtu_list_find(ifi_index);

    if (if_mtu_list_entry == NULL)
        if_mtu_list_entry = if_mtu_list_real_add(ifi_index);

    ph = nfq_get_msg_packet_hdr(nfa);
    id = ntohl(ph->packet_id);

    if (pkBuff == NULL)
        return nfq_set_verdict(qh, id, NF_ACCEPT, 0, NULL);

    /* We must not exceed MTU size when adding options. */
    if (len + IP_OPTIONS_LEN > if_mtu_list_entry->mtu)
    {
        pktb_free(pkBuff);
        return nfq_set_verdict(qh, id, NF_ACCEPT, 0, NULL);
    }

    ip_hdr = nfq_ip_get_hdr(pkBuff);
    if (ip_hdr != NULL)
    {
        nfq_ip_set_transport_header(pkBuff, ip_hdr);
        packet_iterator = (uint8_t *)ip_hdr + len  + 3;
        ip_proto = ip_hdr->protocol;
        if (ip_proto == IPPROTO_TCP || ip_proto == IPPROTO_UDP)
        {
            if (ip_proto == IPPROTO_TCP)
                hdr = nfq_tcp_get_hdr(pkBuff);
            else
                hdr = nfq_udp_get_hdr(pkBuff);

            if (hdr != NULL)
            {
                fin = (uint8_t *)hdr + IP_OPTIONS_LEN;
                add_ip_options(ip_hdr, packet_iterator, fin);
                rc = nfq_set_verdict(qh, id, NF_ACCEPT, len + IP_OPTIONS_LEN,
                                     pktb_data(pkBuff));
                pktb_free(pkBuff);
                return rc;
            }
        }
    }

    pktb_free(pkBuff);
    return nfq_set_verdict(qh, id, NF_ACCEPT, 0, NULL);
}

/**
 * Create a fork and print child PID.
 * In case that any error occurred while creating
 * NFQUEUE handler print -1 instead of PID.
 *
 * @return     EXIT_SUCCESS if daemon successfully started
 *             EXIT_FAILURE if any error occurred
 */
static int
daemonize(void)
{
    pid_t  pid;
    char   out[MAX_PID_LENGTH] = {0};
    int    fd[2];
    int    rc;
    int    ret = 0;

    if (pipe(fd) != 0)
        exit(EXIT_FAILURE);
    rc = fork();
    if (rc < 0)
    {
        exit(EXIT_FAILURE);
    }
    else if (rc == 0)
    {
        pid = getpid();

        nfqueue_handle = nfq_open();
        if (nfqueue_handle == NULL)
        {
            PRINT_LOG(0, "nfq_daemon: nfq_open() returned "
                      "unexpeced result: NULL\n", false, NULL);
            pid = -1;
            goto cleanup;
        }

        if ((ret = nfq_unbind_pf(nfqueue_handle, AF_INET)) < 0)
        {
            PRINT_LOG(ret, NULL, true, NULL);
            nfq_close(nfqueue_handle);
            pid = -1;
            goto cleanup;
        }

        if ((ret = nfq_bind_pf(nfqueue_handle, AF_INET)) < 0)
        {
            PRINT_LOG(ret, NULL, true, NULL);
            nfq_close(nfqueue_handle);
            pid = -1;
            goto cleanup;
        }

        qh = nfq_create_queue(nfqueue_handle, 0, &packet_mangling, NULL);
        if (qh == NULL)
        {
            PRINT_LOG(0, "nfq_daemon: nfq_create_queue() returned "
                      "unexpeced result: NULL\n", false, NULL);
            pid = -1;
            goto cleanup;
        }

        if ((ret = nfq_set_mode(qh, NFQNL_COPY_PACKET, MAX_PACKET_SIZE)) < 0)
        {
            PRINT_LOG(ret, NULL, true, NULL);
            nfq_destroy_queue(qh);
            nfq_close(nfqueue_handle);
            pid = -1;
            goto cleanup;
        }
        if ((ret = nfnl_rcvbufsiz(nfq_nfnlh(nfqueue_handle), MAX_PACKET_SIZE)) < 0)
        {
            PRINT_LOG(ret, NULL, true, NULL);
            nfq_destroy_queue(qh);
            nfq_close(nfqueue_handle);
            pid = -1;
        }

cleanup:
        if ((ret = snprintf(out, sizeof(out), "%d", pid)) <= 0)
        {
            PRINT_LOG(ret, NULL, true, NULL);
            return EXIT_FAILURE;
        }

        if ((ret = write(fd[1], out, strlen(out))) <= 0)
        {
            PRINT_LOG(ret, NULL, true, NULL);
            return EXIT_FAILURE;
        }

        if (pid == -1)
            return EXIT_FAILURE;
    }
    else
    {
        if ((ret = read(fd[0], out, MAX_PID_LENGTH)) <=  0)
        {
            PRINT_LOG(ret, NULL, true, NULL);
            exit(EXIT_FAILURE);
        }

        pid = atoi(out);
        if ((ret = printf("%d", pid)) < 0)
        {
            PRINT_LOG(ret, NULL, true, NULL);
            exit(EXIT_FAILURE);
        }
        exit(EXIT_SUCCESS);
    }

    CHECK_ERRNO_RET(close(fd[0]));
    CHECK_ERRNO_RET(close(fd[1]));
    if (setsid() == -1)
    {
        PRINT_LOG(-1, NULL, true, NULL);
        return EXIT_FAILURE;
    }
    CHECK_ERRNO_RET(close(fileno(stdin)));
    CHECK_ERRNO_RET(close(fileno(stderr)));
    CHECK_ERRNO_RET(close(fileno(stdout)));
    return EXIT_SUCCESS;
}

int
get_netlink_socket()
{
    struct sockaddr_nl addr;
    int sock = socket(AF_NETLINK, SOCK_RAW | SOCK_NONBLOCK, NETLINK_ROUTE);

    memset((void *)&addr, 0, sizeof(addr));

    addr.nl_family = AF_NETLINK;
    addr.nl_pid = getpid();
    addr.nl_groups = RTMGRP_LINK;

    if (bind(sock, (struct sockaddr *)&addr, sizeof(addr)) < 0)
        return -1;

    return sock;
}

int
set_nonblock(int fd)
{
    int flags = fcntl(fd, F_GETFL, 0);
    flags = flags | O_NONBLOCK;
    return fcntl(fd, F_SETFL, flags);
}

/**
 * Start a daemon that will open nfqueue hangler which binds to queue 0.
 * Set a @b packet_mangling as a callback function for every packet in this queue.
 *
 * @return EXIT_SUCCESS If all packets from queue 0 was sent to callback function
 *                      and after that queue was successfully destroed.
 *         EXIT_FAILURE Otherwise.
 */
int
main(void)
{
    int                   nfqueue_fd;
    int                   netlink_fd;
    char                  buf[MAX_PACKET_SIZE] __attribute__ ((aligned));
    int                   rv = 0;
    int                   nfds = 2;
    struct pollfd         pfds[nfds];

    PRINT_LOG(0, "nfq_daemon: starting\n", false, NULL);

    CHECK_ERRNO_RET(daemonize());

    PRINT_LOG(0, "nfq_daemon: successfully started\n", false, NULL);

    nfqueue_fd = nfq_fd(nfqueue_handle);
    netlink_fd = get_netlink_socket();
    if (netlink_fd < 0)
    {
        PRINT_LOG(netlink_fd, NULL, true, NULL);
        return EXIT_FAILURE;
    }

    pfds[0].fd = netlink_fd;
    pfds[0].events = POLLIN;

    if ((rv = set_nonblock(nfqueue_fd)) < 0)
    {
        PRINT_LOG(rv, NULL, true, NULL);
        return EXIT_FAILURE;
    }
    pfds[1].fd = nfqueue_fd;
    pfds[1].events = POLLIN;

    while ((rv = poll(pfds, nfds, -1)) > 0)
    {
        if (pfds[0].revents & POLLIN)
        {
            while ((rv = read(pfds[0].fd, buf, sizeof(buf))) > 0)
                process_netlink_message(buf, rv, NULL);
        }
        if (pfds[1].revents & POLLIN)
        {
            while ((rv = read(pfds[1].fd, buf, sizeof(buf))) > 0)
                nfq_handle_packet(nfqueue_handle, buf, rv);
        }
    }

    PRINT_LOG(rv, NULL, false,
              "nfq_daemon: failed after unexpected poll error "
              "poll return: %d, errno: %s\n",
              rv, strerror(errno));

    CHECK_ERRNO_RET(nfq_destroy_queue(qh));
    CHECK_ERRNO_RET(nfq_close(nfqueue_handle));

    return EXIT_SUCCESS;
}
