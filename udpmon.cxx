#include <iostream>
#include <vector>

#include <string.h>
#include <unistd.h>

#include <linux/netlink.h>
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

int send_request(int fd)
{
    // target address: simply AF_NETLINK.
    sockaddr_nl sa;
    ::memset(&sa, 0, sizeof(sa));
    sa.nl_family = AF_NETLINK;

    // payload
    inet_diag_req_v2 req;
    ::memset(&req, 0, sizeof(req));
    req.sdiag_family = AF_INET;
    req.sdiag_protocol = IPPROTO_TCP;
    req.idiag_states = ALL_SOCKET_STATES;
    req.idiag_ext |= (1 << (INET_DIAG_MEMINFO - 1));

    // header
    nlmsghdr nlh;
    ::memset(&nlh, 0, sizeof(nlh));
    nlh.nlmsg_len = NLMSG_LENGTH(sizeof(req));
    nlh.nlmsg_flags = NLM_F_DUMP | NLM_F_REQUEST;
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
    std::cout << "inet_diag_msg:" << std::endl;
    std::cout << "  state: " << diag_msg->idiag_state << std::endl;
    std::cout << "  inode: " << diag_msg->idiag_inode << std::endl;
    std::cout << "  rqueue: " << diag_msg->idiag_rqueue << std::endl;
    std::cout << "  wqueue: " << diag_msg->idiag_wqueue << std::endl;
}

int recv_message(int fd)
{
    std::vector<uint8_t> recv_buf(SOCKET_BUFFER_SIZE, 0);
    int num_bytes_received = 0;

    num_bytes_received = recv(fd, &recv_buf[0], recv_buf.size(), 0);

    // check header
    nlmsghdr* nlh = (nlmsghdr*)&recv_buf[0];

    while (NLMSG_OK(nlh, num_bytes_received))
    {
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
    int fd = socket(AF_NETLINK, SOCK_DGRAM, NETLINK_INET_DIAG);
    if (fd < 0)
    {
        int tmp = errno;
        std::cout << "Creating socket failed! " << fd << tmp << std::endl;
        exit(tmp);
    }

    // send netlink inet diag request
    int sent = send_request(fd);
    if (sent < 0)
    {
        int tmp = errno;
        std::cout << "Sending message failed! " << sent << tmp << std::endl;
        exit(tmp);
    }

    // receive answer(s)
    while (1)
    {
        recv_message(fd);


    }
}
