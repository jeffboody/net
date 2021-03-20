/*
 * Copyright (c) 2013 Jeff Boody
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

#ifndef net_socket_H
#define net_socket_H

// type
// Note that TCP uses Nagle's algorithm to buffer data until
// ACK is received.
// Note that UDP is not supported for SSL.
#define NET_SOCKET_TYPE_TCP 0
#define NET_SOCKET_TYPE_UDP 1
#define NET_SOCKET_TYPE_MAX 2

// shutdown "how"
#define NET_SOCKET_HOW_SHUT_RD   0
#define NET_SOCKET_HOW_SHUT_WR   1
#define NET_SOCKET_HOW_SHUT_RDWR 2

// flags
// Note that FLAG_TCP_NODELAY causes send data to be sent
// immediately for low latency but causes higher overhead.
// Note that FLAG_TCP_BUFFERED sends data when buffer is
// full or flushed and that a flush may be needed before
// receiving data to ensure that the remote receives the
// packets for which it is expected to respond.
// Note that the default implementation behavior for NET
// with the SSL flag is SSL_VERIFY_PEER on the client and
// SSL_VERIFY_PEER/SSL_VERIFY_FAIL_IF_NO_PEER_CERT on the
// server.
// The CONNECT_INSECURE flag is equivalent to the CURL
// option --insecure or wget option --no-check-certificate
// and is insecure as the name implies.
// The LISTEN_ANYONE flag may be used for servers which do
// not need to verify their client such as an https server.
#define NET_SOCKET_FLAG_TCP_NODELAY          0x0001
#define NET_SOCKET_FLAG_TCP_BUFFERED         0x0002
#define NET_SOCKET_FLAG_SSL                  0x1000
#define NET_SOCKET_FLAG_SSL_CONNECT_INSECURE 0x2000
#define NET_SOCKET_FLAG_SSL_LISTEN_ANYONE    0x4000

typedef int (*net_socket_requestFn)(void* priv,
                                    const char* request,
                                    int* _size,
                                    void** _data);

typedef struct
{
	int type;
	int flags;
	int sockfd;
	int connected;
	int error;

	// HTTP host - "addr:port"
	char host[256];

	// only valid for BUFFERED
	unsigned int   len;
	unsigned char* buffer;
} net_socket_t;

typedef struct
{
	const char* addr;
	const char* port;
	const char* ca_cert;
	const char* client_cert;
	const char* client_key;
	int         type;
	int         flags;
} net_connectInfo_t;

typedef struct
{
	const char* port;
	const char* ca_cert;
	const char* server_cert;
	const char* server_key;
	int         type;
	int         flags;
} net_listenInfo_t;

net_socket_t* net_socket_connect(net_connectInfo_t* info);
net_socket_t* net_socket_listen(net_listenInfo_t* info);
net_socket_t* net_socket_accept(net_socket_t* self);
int           net_socket_shutdown(net_socket_t* self,
                                  int how);
void          net_socket_close(net_socket_t** _self);
int           net_socket_keepalive(net_socket_t* self,
                                   int cnt,
                                   int idle,
                                   int intvl);
void          net_socket_timeout(net_socket_t* self,
                                 int recv_to,
                                 int send_to);
int           net_socket_sendall(net_socket_t* self,
                                 const void* data,
                                 int len);
int           net_socket_flush(net_socket_t* self);
int           net_socket_recv(net_socket_t* self,
                              void* data,
                              int len,
                              int* recvd);
int           net_socket_recvall(net_socket_t* self,
                                 void* data,
                                 int len,
                                 int* recvd);
int           net_socket_error(net_socket_t* self);
int           net_socket_connected(net_socket_t* self);
int           net_socket_wget(net_socket_t* self,
                              const char* user_agent,
                              const char* request,
                              int close,
                              int* _size, void** _data);
int           net_socket_wserve(net_socket_t* self, int chunked,
                                void* request_priv,
                                net_socket_requestFn request_fn,
                                int* close);
int           net_socket_requestFile(void* priv,
                                     const char* request,
                                     int* _size,
                                     void** _data);

#endif
