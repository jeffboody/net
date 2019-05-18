/*
 * Copyright (c) 2019 Jeff Boody
 *
 * Permission is hereby granted, free of charge, to any person obtaining a
 * copy of this software and associated documentation files (the "Software"),
 * to deal in the Software without restriction, including without limitation
 * the rights to use, copy, modify, merge, publish, distribute, sublicense,
 * and/or sell copies of the Software, and to permit persons to whom the
 * Software is furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included
 * in all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 *
 */

#ifndef net_socketSSL_H
#define net_socketSSL_H

#include <openssl/ssl.h>

// type
// TCP: use Nagle's algorithm to buffer data until ACK is received
// TCP_NODELAY: send data immediately for low latency but higher overhead
// TCP_BUFFERED: send data when buffer is full or flushed
// Note that when using TCP_BUFFERED a flush may be needed before receiving
// data to ensure that the remote receives the packets for which it is
// expected to respond.
#define NET_SOCKETSSL_TCP          0
#define NET_SOCKETSSL_TCP_NODELAY  1
#define NET_SOCKETSSL_TCP_BUFFERED 2

// shutdown "how"
#define NET_SOCKETSSL_SHUT_RD   0
#define NET_SOCKETSSL_SHUT_WR   1
#define NET_SOCKETSSL_SHUT_RDWR 2

#define NET_SOCKETSSL_METHOD_CLIENT 0
#define NET_SOCKETSSL_METHOD_SERVER 1
#define NET_SOCKETSSL_METHOD_ACCEPT 2

typedef struct
{
	int type;
	int sockfd;
	int connected;
	int error;

	// HTTP host - "addr:port"
	char host[256];

	// only valid for TCP_BUFFERED
	unsigned int   len;
	unsigned char* buffer;

	// SSL state
	int      method;
	SSL_CTX* ctx;
	SSL*     ssl;
} net_socketSSL_t;

net_socketSSL_t* net_socketSSL_connect(const char* addr,
                                       const char* port,
                                       int type);
net_socketSSL_t* net_socketSSL_listen(const char* port,
                                      int type,
                                      int backlog);
net_socketSSL_t* net_socketSSL_accept(net_socketSSL_t* self);
int              net_socketSSL_shutdown(net_socketSSL_t* self,
                                        int how);
void             net_socketSSL_close(net_socketSSL_t** _self);
int              net_socketSSL_keepalive(net_socketSSL_t* self,
                                      int cnt, int idle, int intvl);
void             net_socketSSL_timeout(net_socketSSL_t* self,
                                    int recv_to, int send_to);
int              net_socketSSL_sendall(net_socketSSL_t* self,
                                       const void* data,
                                       int len);
int              net_socketSSL_flush(net_socketSSL_t* self);
int              net_socketSSL_recv(net_socketSSL_t* self,
                                    void* data,
                                    int len,
                                    int* recvd);
int              net_socketSSL_recvall(net_socketSSL_t* self,
                                       void* data,
                                       int len,
                                       int* recvd);
int              net_socketSSL_error(net_socketSSL_t* self);
int              net_socketSSL_connected(net_socketSSL_t* self);

#endif
