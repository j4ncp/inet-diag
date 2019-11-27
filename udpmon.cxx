#include <iostream>
#include <vector>
#include <chrono>

#include <string.h>
#include <unistd.h>

#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <linux/sock_diag.h>
#include <linux/inet_diag.h>
#include <linux/udp.h>

#include <arpa/inet.h>

#include <sys/types.h>
#include <sys/socket.h>

#include <netinet/in.h>

#include <errno.h>

#define ALL_SOCKET_STATES 0xFFF

#define SOCKET_BUFFER_SIZE (getpagesize() < 8192L ? getpagesize() : 8192L)

/*

   IPv4 and IPv6 sockets
       For IPv4 and IPv6 sockets, the request is represented in the follow‐
       ing structure:

           struct inet_diag_req_v2 {
               __u8    sdiag_family;
               __u8    sdiag_protocol;
               __u8    idiag_ext;
               __u8    pad;
               __u32   idiag_states;
               struct inet_diag_sockid id;
           };

       where struct inet_diag_sockid is defined as follows:

           struct inet_diag_sockid {
               __be16  idiag_sport;
               __be16  idiag_dport;
               __be32  idiag_src[4];
               __be32  idiag_dst[4];
               __u32   idiag_if;
               __u32   idiag_cookie[2];
           };

       The fields of struct inet_diag_req_v2 are as follows:

       sdiag_family
              This should be set to either AF_INET or AF_INET6 for IPv4 or
              IPv6 sockets respectively.

       sdiag_protocol
              This should be set to one of IPPROTO_TCP, IPPROTO_UDP, or
              IPPROTO_UDPLITE.

       idiag_ext
              This is a set of flags defining what kind of extended informa‐
              tion to report.  Each requested kind of information is
              reported back as a netlink attribute as described below:

              INET_DIAG_TOS
                     The payload associated with this attribute is a __u8
                     value which is the TOS of the socket.

              INET_DIAG_TCLASS
                     The payload associated with this attribute is a __u8
                     value which is the TClass of the socket.  IPv6 sockets
                     only.  For LISTEN and CLOSE sockets, this is followed
                     by INET_DIAG_SKV6ONLY attribute with associated __u8
                     payload value meaning whether the socket is IPv6-only
                     or not.

              INET_DIAG_MEMINFO
                     The payload associated with this attribute is repre‐
                     sented in the following structure:

                         struct inet_diag_meminfo {
                             __u32 idiag_rmem;
                             __u32 idiag_wmem;
                             __u32 idiag_fmem;
                             __u32 idiag_tmem;
                         };

                     The fields of this structure are as follows:

                     idiag_rmem  The amount of data in the receive queue.

                     idiag_wmem  The amount of data that is queued by TCP
                                 but not yet sent.

                     idiag_fmem  The amount of memory scheduled for future
                                 use (TCP only).

                     idiag_tmem  The amount of data in send queue.

              INET_DIAG_SKMEMINFO
                     The payload associated with this attribute is an array
                     of __u32 values described below in the subsection
                     "Socket memory information".

              INET_DIAG_INFO
                     The payload associated with this attribute is specific
                     to the address family.  For TCP sockets, it is an
                     object of type struct tcp_info.

              INET_DIAG_CONG
                     The payload associated with this attribute is a string
                     that describes the congestion control algorithm used.
                     For TCP sockets only.

       pad    This should be set to 0.

       idiag_states
              This is a bit mask that defines a filter of socket states.
              Only those sockets whose states are in this mask will be
              reported.  Ignored when querying for an individual socket.

       id     This is a socket ID object that is used in dump requests, in
              queries about individual sockets, and is reported back in each
              response.  Unlike UNIX domain sockets, IPv4 and IPv6 sockets
              are identified using addresses and ports.  All values are in
              network byte order.

       The fields of struct inet_diag_sockid are as follows:

       idiag_sport
              The source port.

       idiag_dport
              The destination port.

       idiag_src
              The source address.

       idiag_dst
              The destination address.

       idiag_if
              The interface number the socket is bound to.

       idiag_cookie
              This is an array of opaque identifiers that could be used
              along with other fields of this structure to specify an indi‐
              vidual socket.  It is ignored when querying for a list of
              sockets, as well as when all its elements are set to -1.

       The response to a query for IPv4 or IPv6 sockets is represented as an
       array of

           struct inet_diag_msg {
               __u8    idiag_family;
               __u8    idiag_state;
               __u8    idiag_timer;
               __u8    idiag_retrans;

               struct inet_diag_sockid id;

               __u32   idiag_expires;
               __u32   idiag_rqueue;
               __u32   idiag_wqueue;
               __u32   idiag_uid;
               __u32   idiag_inode;
           };

       followed by netlink attributes.

       The fields of this structure are as follows:

       idiag_family
              This is the same field as in struct inet_diag_req_v2.

       idiag_state
              This denotes socket state as in struct inet_diag_req_v2.

       idiag_timer
              For TCP sockets, this field describes the type of timer that
              is currently active for the socket.  It is set to one of the
              following constants:

                   0      no timer is active
                   1      a retransmit timer
                   2      a keep-alive timer
                   3      a TIME_WAIT timer
                   4      a zero window probe timer

              For non-TCP sockets, this field is set to 0.

       idiag_retrans
              For idiag_timer values 1, 2, and 4, this field contains the
              number of retransmits.  For other idiag_timer values, this
              field is set to 0.

       idiag_expires
              For TCP sockets that have an active timer, this field
              describes its expiration time in milliseconds.  For other
              sockets, this field is set to 0.

       idiag_rqueue
              For listening sockets: the number of pending connections.

              For other sockets: the amount of data in the incoming queue.

       idiag_wqueue
              For listening sockets: the backlog length.

              For other sockets: the amount of memory available for sending.

       idiag_uid
              This is the socket owner UID.

       idiag_inode
              This is the socket inode number.
              
  -------------------------------------------------------------------------

Socket memory information

       The payload associated with UNIX_DIAG_MEMINFO and INET_DIAG_SKMEMINFO
       netlink attributes is an array of the following __u32 values:

       SK_MEMINFO_RMEM_ALLOC
              The amount of data in receive queue.

       SK_MEMINFO_RCVBUF
              The receive socket buffer as set by SO_RCVBUF.

       SK_MEMINFO_WMEM_ALLOC
              The amount of data in send queue.

       SK_MEMINFO_SNDBUF
              The send socket buffer as set by SO_SNDBUF.

       SK_MEMINFO_FWD_ALLOC
              The amount of memory scheduled for future use (TCP only).

       SK_MEMINFO_WMEM_QUEUED
              The amount of data queued by TCP, but not yet sent.

       SK_MEMINFO_OPTMEM
              The amount of memory allocated for the socket's service needs
              (e.g., socket filter).

       SK_MEMINFO_BACKLOG
              The amount of packets in the backlog (not yet processed).

*/

int send_request(int fd, uint16_t port)
{
    // target address: simply AF_NETLINK.
    sockaddr_nl sa;
    ::memset(&sa, 0, sizeof(sa));
    sa.nl_family = AF_NETLINK;

    // payload
    inet_diag_req_v2 req;
    ::memset(&req, 0, sizeof(req));
    req.sdiag_family = AF_INET;
    req.sdiag_protocol = IPPROTO_UDP;
    req.idiag_states = ALL_SOCKET_STATES;
    req.idiag_ext |= (1 << (INET_DIAG_MEMINFO - 1));
    req.idiag_ext |= (1 << (INET_DIAG_SKMEMINFO - 1));

    // socket to ask info about:
    req.id.idiag_dport = htons(port);
    req.id.idiag_cookie[0] = INET_DIAG_NOCOOKIE;
    req.id.idiag_cookie[1] = INET_DIAG_NOCOOKIE;
    

    // header
    nlmsghdr nlh;
    ::memset(&nlh, 0, sizeof(nlh));
    nlh.nlmsg_len = NLMSG_LENGTH(sizeof(req));
    nlh.nlmsg_flags = NLM_F_REQUEST;// | NLM_F_DUMP;
    nlh.nlmsg_type = SOCK_DIAG_BY_FAMILY;

    // compose message
    iovec iov[2];
    iov[0].iov_base = &nlh;
    iov[0].iov_len = sizeof(nlh);
    iov[1].iov_base = &req;
    iov[1].iov_len = sizeof(req);

    msghdr msg;
    ::memset(&msg, 0, sizeof(msg));
    msg.msg_name = &sa;
    msg.msg_namelen = sizeof(sa);
    msg.msg_iov= iov;
    msg.msg_iovlen = 2;

    return sendmsg(fd, &msg, 0);
}

void parse_recv_message(inet_diag_msg* diag_msg, int rtalen)
{
    std::cout << "INET_DIAG:" << std::endl;
    std::cout << "  inet_diag_msg:" << std::endl;
    std::cout << "    dport: " << ntohs(diag_msg->id.idiag_sport) << std::endl;
    std::cout << "    sport: " << ntohs(diag_msg->id.idiag_dport) << std::endl;
    std::cout << "    cookies: " << diag_msg->id.idiag_cookie[0] << " " << diag_msg->id.idiag_cookie[1] << std::endl;
    std::cout << "    state: " << (int)diag_msg->idiag_state << std::endl;
    std::cout << "    inode: " << diag_msg->idiag_inode << std::endl;
    std::cout << "    rqueue: " << diag_msg->idiag_rqueue << std::endl;
    std::cout << "    wqueue: " << diag_msg->idiag_wqueue << std::endl;
    
    // parse extensions
    if (rtalen > 0)
    {
        rtattr* attr = (rtattr*)(diag_msg+1);
        while (RTA_OK(attr, rtalen))
        {
            std::cout << "Parsing next rtattr" << std::endl;
            
            // check which type of extension data this is
            if (attr->rta_type == INET_DIAG_MEMINFO)
            {
                // cast to struct
                inet_diag_meminfo* mi = (inet_diag_meminfo*)RTA_DATA(attr);
                
                std::cout << "  inet_diag_meminfo:" << std::endl;
                std::cout << "    idiag_rmem: " << mi->idiag_rmem << std::endl;
                std::cout << "    idiag_wmem: " << mi->idiag_wmem << std::endl;
                std::cout << "    idiag_fmem: " << mi->idiag_fmem << std::endl;
                std::cout << "    idiag_tmem: " << mi->idiag_tmem << std::endl;
            }
            else if (attr->rta_type == INET_DIAG_SKMEMINFO)
            {
                // cast to data pointer
                uint32_t* skmem = (uint32_t*)RTA_DATA(attr);
                
                std::cout << "  sk mem info:" << std::endl;
                std::cout << "    mem[SK_MEMINFO_RMEM_ALLOC] = " << skmem[SK_MEMINFO_RMEM_ALLOC] << std::endl;
                std::cout << "    mem[SK_MEMINFO_WMEM_ALLOC] = " << skmem[SK_MEMINFO_WMEM_ALLOC] << std::endl;
                std::cout << "    mem[SK_MEMINFO_RCVBUF] = " << skmem[SK_MEMINFO_RCVBUF] << std::endl;
                std::cout << "    mem[SK_MEMINFO_SNDBUF] = " << skmem[SK_MEMINFO_SNDBUF] << std::endl;
                std::cout << "    mem[SK_MEMINFO_FWD_ALLOC] = " << skmem[SK_MEMINFO_FWD_ALLOC] << std::endl;
                std::cout << "    mem[SK_MEMINFO_WMEM_QUEUED] = " << skmem[SK_MEMINFO_WMEM_QUEUED] << std::endl;
                std::cout << "    mem[SK_MEMINFO_OPTMEM] = " << skmem[SK_MEMINFO_OPTMEM] << std::endl;
                std::cout << "    mem[SK_MEMINFO_BACKLOG] = " << skmem[SK_MEMINFO_BACKLOG] << std::endl;
                std::cout << "    mem[SK_MEMINFO_DROPS] = " << skmem[SK_MEMINFO_VARS] << std::endl;
            }
            attr = RTA_NEXT(attr, rtalen);
        }
    }
}

int recv_message(int fd)
{
    std::vector<uint8_t> recv_buf(SOCKET_BUFFER_SIZE, 0);
    int num_bytes_received = 0;

    num_bytes_received = recv(fd, &recv_buf[0], recv_buf.size(), 0);
    
    std::cout << "Received " << num_bytes_received << " bytes" << std::endl;

    // check header
    nlmsghdr* nlh = (nlmsghdr*)&recv_buf[0];

    while (NLMSG_OK(nlh, num_bytes_received))
    {
        std::cout << "Parsing next nlmsghdr" << std::endl;
        if (nlh->nlmsg_type == NLMSG_DONE)
            exit(EXIT_SUCCESS);
        if (nlh->nlmsg_type == NLMSG_ERROR)
        {
            std::cout << "Error in received netlink message:" << std::endl;
            nlmsgerr* err_msg = (nlmsgerr*)NLMSG_DATA(nlh);
            std::cout << "  errno: " << err_msg->error << std::endl;

            if (err_msg->error == -ENOENT)
            {
                std::cout << "  Diagnostics functionality not supported by kernel!" << std::endl;
            }

            exit(EXIT_FAILURE);
        }

        // message payload
        inet_diag_msg* diag_msg = (inet_diag_msg*)NLMSG_DATA(nlh);
        int rtalen = nlh->nlmsg_len - NLMSG_LENGTH(sizeof(*diag_msg));

        parse_recv_message(diag_msg, rtalen);

        nlh = NLMSG_NEXT(nlh, num_bytes_received);
    }

    return 0;
}


int main(int argc, char* argv[])
{
    // argv[1] should be the local port of the receiving UDP socket
    if (argc < 2)
    {
        std::cout << "Give the local port of the UDP socket as argument!" << std::endl;
        exit(EXIT_FAILURE);
    }
    uint16_t port = (uint16_t)atoi(argv[1]);
    
    // now
    auto now_d = std::chrono::high_resolution_clock::now().time_since_epoch();
    uint64_t micros = std::chrono::duration_cast<std::chrono::microseconds>(now_d).count();

    // timestamp
    double ts = micros * 10e-6;
    
    printf("Time: %.4f\n", ts);

    int fd = socket(AF_NETLINK, SOCK_DGRAM, NETLINK_INET_DIAG);
    if (fd < 0)
    {
        int tmp = errno;
        std::cout << "Creating socket failed! " << fd << tmp << std::endl;
        exit(tmp);
    }

    // send netlink inet diag request
    int sent = send_request(fd, port);
    if (sent < 0)
    {
        int tmp = errno;
        std::cout << "Sending message failed! " << sent << tmp << std::endl;
        exit(tmp);
    }

    // receive answer(s)
    while (1)
    {
        std::cout << "Receiving next answer packet" << std::endl;
        recv_message(fd);
    }
}
