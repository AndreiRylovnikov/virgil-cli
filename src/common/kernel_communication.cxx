/**
 * Copyright (C) 2016 Virgil Security Inc.
 *
 * Lead Maintainer: Virgil Security Inc. <support@virgilsecurity.com>
 *
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are
 * met:
 *
 *     (1) Redistributions of source code must retain the above copyright
 *     notice, this list of conditions and the following disclaimer.
 *
 *     (2) Redistributions in binary form must reproduce the above copyright
 *     notice, this list of conditions and the following disclaimer in
 *     the documentation and/or other materials provided with the
 *     distribution.
 *
 *     (3) Neither the name of the copyright holder nor the names of its
 *     contributors may be used to endorse or promote products derived from
 *     this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ''AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT,
 * INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING
 * IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

#if defined(__linux)

#include "cli/kernel_communication.h"

#include <sys/types.h>
#include <sys/socket.h>
#include <linux/netlink.h>
#include <iostream>
#include <cstdlib>
#include <cstring>
#include <unistd.h>

#include <virgil/crypto/VirgilByteArrayUtils.h>

namespace virgil { namespace crypto {
    
    bool VirgilKernelCommunicator::send(const std::string & requestID, const std::string & command, const VirgilByteArray & data) {
        VirgilByteArray package;
        
        package.insert(package.end(), requestID.begin(), requestID.end());
        package.push_back(0);
        
        package.insert(package.end(), command.begin(), command.end());
        package.push_back(0);
        
        package.insert(package.end(), data.begin(), data.end());
        
        struct sockaddr_nl s_nladdr, d_nladdr;
        struct msghdr msg;
        struct nlmsghdr *nlh = NULL;
        struct iovec iov;
        int fd = socket(AF_NETLINK, SOCK_RAW, VirgilKernelCommunicator::_virgilNetlink);

        /* source address */
        memset(&s_nladdr, 0, sizeof (s_nladdr));
        s_nladdr.nl_family = AF_NETLINK;
        s_nladdr.nl_pad = 0;
        s_nladdr.nl_pid = getpid();
        if (0 != bind(fd, (struct sockaddr*) &s_nladdr, sizeof (s_nladdr))) {
            return false;
        }

        /* destination address */
        memset(&d_nladdr, 0, sizeof (d_nladdr));
        d_nladdr.nl_family = AF_NETLINK;
        d_nladdr.nl_pad = 0;
        d_nladdr.nl_pid = 0; /* destined to kernel */

        /* Fill the netlink message header */
        const size_t _sz(sizeof(struct nlmsghdr) + package.size());
        nlh = (struct nlmsghdr *) malloc(_sz);
        memset(nlh, 0, _sz);
        memcpy(NLMSG_DATA(nlh), package.data(), package.size());
        nlh->nlmsg_len = _sz;
        nlh->nlmsg_pid = getpid();
        nlh->nlmsg_flags = 1;
        nlh->nlmsg_type = 0;

        /*iov structure */
        iov.iov_base = (void *) nlh;
        iov.iov_len = nlh->nlmsg_len;

        /* msg */
        memset(&msg, 0, sizeof (msg));
        msg.msg_name = (void *) &d_nladdr;
        msg.msg_namelen = sizeof (d_nladdr);
        msg.msg_iov = &iov;
        msg.msg_iovlen = 1;
        sendmsg(fd, &msg, 0);

        close(fd);

        return true;
    }
    
}}

#endif /* __linux */
