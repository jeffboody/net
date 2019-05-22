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

#include <stdlib.h>
#include <assert.h>
#include <string.h>
#include <stdio.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/select.h>
#include <sys/socket.h>
#ifdef __APPLE__
	// for select on iOS
	#include "TargetConditionals.h"
	#if TARGET_OS_IPHONE || TARGET_IPHONE_SIMULATOR
		#include <sys/time.h>
	#endif
#endif
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <netdb.h>
#include <signal.h>
#include <unistd.h>
#include <openssl/err.h>

#include "net_socketSSL.h"

#define LOG_TAG "net"
#include "net_log.h"

/***********************************************************
* private                                                  *
***********************************************************/

#define NET_SOCKETSSL_BUFSIZE 64*1024

static int
send_buffered(net_socketSSL_t* self,
              const void* data, int len)
{
	assert(self);
	assert(self->buffer);
	assert(data);
	// skip LOGD

	// buffer data
	int len_free = NET_SOCKETSSL_BUFSIZE - self->len;
	int len_copy = (len_free >= len) ? len : len_free;
	void* dst = (void*) (self->buffer + self->len);
	memcpy(dst, data, len_copy);
	self->len += len_copy;

	// flush
	if(self->len == NET_SOCKETSSL_BUFSIZE)
	{
		if(net_socketSSL_flush(self) == 0)
		{
			return 0;
		}
	}

	return len_copy;
}

static int
sendall(net_socketSSL_t* self,
        const void* data, int len, int buffered)
{
	assert(self);
	assert(data);

	int left        = len;
	const void* buf = data;
	while(left > 0)
	{
		int count = 0;
		if(buffered)
		{
			count = send_buffered(self, buf, left);
		}
		else if(self->connected)
		{
			count = SSL_write(self->ssl, buf, left);
		}

		if(count <= 0)
		{
			if(self->error == 0)
			{
				LOGD("SSL_write failed");
			}
			self->error     = 1;
			self->connected = 0;
			return 0;
		}
		left = left - count;
		buf  = buf + count;
	}
	return 1;
}

static int
net_socketSSL_connectTimeout(net_socketSSL_t* self,
                             struct addrinfo* i)
{
	assert(self);
	assert(i);

	// Note: use example.com:81 to test timeouts

	// set the non-blocking flag
	int flags = fcntl(self->sockfd, F_GETFL, 0);
	fcntl(self->sockfd, F_SETFL, flags | O_NONBLOCK);

	int c = connect(self->sockfd, i->ai_addr, i->ai_addrlen);
	if((c == -1) && (errno == EINPROGRESS))
	{
		// complete connection with timeout
		struct timeval timeout;
		timeout.tv_sec  = 4;
		timeout.tv_usec = 0;

		fd_set fdset;
		FD_ZERO(&fdset);
		FD_SET(self->sockfd, &fdset);

		int s = select(self->sockfd + 1, NULL,
		               &fdset, NULL, &timeout);
		if(s == 0)
		{
			LOGD("select timed out");
			goto fail_select;
		}
		else if(s == -1)
		{
			LOGD("select errno=%i", (int) errno);
			goto fail_select;
		}

		int so_error;
		socklen_t len = sizeof(so_error);
		getsockopt(self->sockfd, SOL_SOCKET, SO_ERROR,
		           &so_error, &len);
		if(so_error != 0)
		{
			LOGD("select so_error=%i", so_error);
			goto fail_connected;
		}
	}
	else if(c == -1)
	{
		LOGD("connect failed errno=%i", (int) errno);
		goto fail_connect;
	}

	// restore the blocking flag
	fcntl(self->sockfd, F_SETFL, flags);

	// init ssl
	self->ssl = SSL_new(self->ctx);
	if(self->ssl == NULL)
	{
		LOGE("SSL_new failed");
		goto fail_ssl;
	}

	if(SSL_set_fd(self->ssl, self->sockfd) != 1)
	{
		LOGE("SSL_set_fd failed");
		goto fail_set_fd;
	}

	if(SSL_connect(self->ssl) != 1)
	{
		LOGE("SSL_connect failed");
		goto fail_ssl_connect;
	}

	if(SSL_get_verify_result(self->ssl) != X509_V_OK)
	{
		LOGE("SSL_get_verify_result failed");
		goto fail_ssl_verify;
	}

	// success
	return 1;

	// failure
	fail_ssl_verify:
	fail_ssl_connect:
	fail_set_fd:
		SSL_free(self->ssl);
	fail_ssl:
	fail_connected:
	fail_select:
	fail_connect:
		// restore the blocking flag
		fcntl(self->sockfd, F_SETFL, flags);
	return 0;
}

/***********************************************************
* public                                                   *
***********************************************************/

net_socketSSL_t*
net_socketSSL_connect(const char* addr,
                      const char* port, int type)
{
	assert(addr);
	assert(port);

	int socktype;
	if((type >= NET_SOCKETSSL_TCP) &&
	   (type <= NET_SOCKETSSL_TCP_BUFFERED))
	{
		socktype = SOCK_STREAM;
	}
	else
	{
		LOGE("invalid type=%i", type);
		return NULL;
	}

	net_socketSSL_t* self;
	self = (net_socketSSL_t*)
	       malloc(sizeof(net_socketSSL_t));
	if(self == NULL)
	{
		LOGE("malloc failed");
		return NULL;
	}

	// SIGPIPE causes the process to exit for broken streams
	// but we want to receive EPIPE instead
	signal(SIGPIPE, SIG_IGN);

	if(type == NET_SOCKETSSL_TCP_BUFFERED)
	{
		self->buffer = (unsigned char*)
		               malloc(NET_SOCKETSSL_BUFSIZE*
		                      sizeof(unsigned char));
		if(self->buffer == NULL)
		{
			LOGE("malloc failed");
			goto fail_buffer;
		}
	}
	else
	{
		self->buffer = NULL;
	}
	self->len = 0;

	// for HTTP
	snprintf(self->host, 256, "%s:%s", addr, port);

	// init SSL ctx
#if NET_SOCKET_USE_OPENSSL_1_1
	self->ctx = SSL_CTX_new(TLS_client_method());
#else
	// app should call SSL_library_init(); prior to creating any
	// OpenSSL sockets with the old API
	self->ctx = SSL_CTX_new(SSLv23_client_method());
#endif
	if(self->ctx == NULL)
	{
		LOGE("SSL_CTX_new failed");
		goto fail_ctx;
	}
	self->method = NET_SOCKETSSL_METHOD_CLIENT;

	if(SSL_CTX_load_verify_locations(self->ctx,
	                                 "ca_cert.pem", NULL) != 1)
	{
		LOGE("SSL_CTX_load_verify_locations failed");
		goto fail_load_verify;
	}

#if NET_SOCKET_USE_OPENSSL_1_1
	if(SSL_CTX_set_default_verify_file(self->ctx) != 1)
	{
		LOGE("SSL_CTX_set_default_verify_file failed");
		goto fail_set_default_verify_file;
	}
#endif

	if(SSL_CTX_use_certificate_file(self->ctx,
	                                "client_cert.pem",
	                                SSL_FILETYPE_PEM) != 1)
	{
		LOGE("SSL_CTX_use_certificate_file failed");
		goto fail_use_cert;
	}

	if(SSL_CTX_use_PrivateKey_file(self->ctx,
	                               "client_key.pem",
	                               SSL_FILETYPE_PEM) != 1)
	{
		LOGE("SSL_CTX_use_PrivateKey_file failed");
		goto fail_use_priv;
	}

	if(SSL_CTX_check_private_key(self->ctx) != 1)
	{
		LOGE("SSL_CTX_check_private_key failed");
		goto fail_check_priv;
	}

	SSL_CTX_set_mode(self->ctx, SSL_MODE_AUTO_RETRY);
	SSL_CTX_set_verify(self->ctx, SSL_VERIFY_PEER, NULL);
	SSL_CTX_set_verify_depth(self->ctx, 1);

	struct addrinfo hints;
	memset(&hints, 0, sizeof(hints));
	hints.ai_family   = AF_UNSPEC;
	hints.ai_socktype = socktype;

	struct addrinfo* info;
	if(getaddrinfo(addr, port, &hints, &info) != 0)
	{
		LOGD("getaddrinfo addr=%s, port=%s, failed",
		     addr, port);
		goto fail_getaddrinfo;
	}

	struct addrinfo* i = info;
	self->sockfd = -1;
	while(i)
	{
		self->sockfd = socket(i->ai_family,
		                      i->ai_socktype,
		                      i->ai_protocol);
		if(self->sockfd == -1)
		{
			LOGD("socket failed");
			i = i->ai_next;
			continue;
		}

		if((type == NET_SOCKETSSL_TCP_NODELAY) ||
		   (type == NET_SOCKETSSL_TCP_BUFFERED))
		{
			int yes = 1;
			if(setsockopt(self->sockfd, IPPROTO_TCP,
			              TCP_NODELAY, (const void*) &yes,
			              sizeof(int)) == -1)
			{
				LOGD("setsockopt TCP_NODELAY failed");
			}
		}

		if(net_socketSSL_connectTimeout(self, i) == 0)
		{
			close(self->sockfd);
			self->sockfd = -1;
			i = i->ai_next;
			continue;
		}

		break;
	}
	freeaddrinfo(info);

	if(self->sockfd == -1)
	{
		LOGD("socket failed");
		goto fail_socket;
	}

	self->error     = 0;
	self->connected = 1;
	self->type      = type;

	// success
	return self;

	// failure
	fail_socket:
	fail_getaddrinfo:
	fail_check_priv:
	fail_use_priv:
	fail_use_cert:
#if NET_SOCKET_USE_OPENSSL_1_1
	fail_set_default_verify_file:
#endif
	fail_load_verify:
		SSL_CTX_free(self->ctx);
	fail_ctx:
		free(self->buffer);
	fail_buffer:
		free(self);
	return NULL;
}

net_socketSSL_t*
net_socketSSL_listen(const char* port, int type,
                     int backlog)
{
	assert(port);
	assert(backlog > 0);

	int socktype;
	if((type >= NET_SOCKETSSL_TCP) &&
	   (type <= NET_SOCKETSSL_TCP_BUFFERED))
	{
		socktype = SOCK_STREAM;
	}
	else
	{
		LOGE("invalid type=%i", type);
		return NULL;
	}

	net_socketSSL_t* self;
	self = (net_socketSSL_t*)
	       malloc(sizeof(net_socketSSL_t));
	if(self == NULL)
	{
		LOGE("malloc failed");
		return NULL;
	}

	// SIGPIPE causes the process to exit for broken streams
	// but we want to receive EPIPE instead
	signal(SIGPIPE, SIG_IGN);

	// init SSL ctx
#if NET_SOCKET_USE_OPENSSL_1_1
	self->ctx = SSL_CTX_new(TLS_server_method());
#else
	// app should call SSL_library_init(); prior to creating any
	// OpenSSL sockets with the old API
	self->ctx = SSL_CTX_new(SSLv23_server_method());
#endif
	if(self->ctx == NULL)
	{
		LOGE("SSL_CTX_new failed");
		goto fail_ctx;
	}
	self->method = NET_SOCKETSSL_METHOD_SERVER;
	self->ssl    = NULL;

	if(SSL_CTX_load_verify_locations(self->ctx,
	                                 "ca_cert.pem", NULL) != 1)
	{
		LOGE("SSL_CTX_load_verify_locations failed");
		goto fail_load_verify;
	}

#if NET_SOCKET_USE_OPENSSL_1_1
	if(SSL_CTX_set_default_verify_file(self->ctx) != 1)
	{
		LOGE("SSL_CTX_set_default_verify_file failed");
		goto fail_set_default_verify_file;
	}
#endif

	STACK_OF(X509_NAME)* cert_names;
	cert_names = SSL_load_client_CA_file("ca_cert.pem");
	if(cert_names == NULL)
	{
		LOGE("SSL_load_client_CA_file failed");
		goto fail_cert_names;
	}
	SSL_CTX_set_client_CA_list(self->ctx, cert_names);

	if(SSL_CTX_use_certificate_file(self->ctx,
	                                "server_cert.pem",
	                                SSL_FILETYPE_PEM) != 1)
	{
		LOGE("SSL_CTX_use_certificate_file failed");
		goto fail_use_cert;
	}

	if(SSL_CTX_use_PrivateKey_file(self->ctx,
	                               "server_key.pem",
	                               SSL_FILETYPE_PEM) != 1)
	{
		LOGE("SSL_CTX_use_PrivateKey_file failed");
		goto fail_use_priv;
	}

	if(SSL_CTX_check_private_key(self->ctx) != 1)
	{
		LOGE("SSL_CTX_check_private_key failed");
		goto fail_check_priv;
	}

	SSL_CTX_set_mode(self->ctx, SSL_MODE_AUTO_RETRY);
	SSL_CTX_set_verify(self->ctx,
	                   SSL_VERIFY_PEER |
	                   SSL_VERIFY_FAIL_IF_NO_PEER_CERT,
	                   NULL);
	SSL_CTX_set_verify_depth(self->ctx, 1);

	// not needed for listening socket
	self->buffer = NULL;
	self->len    = 0;

	struct addrinfo hints;
	memset(&hints, 0, sizeof(hints));
	hints.ai_family   = AF_UNSPEC;
	hints.ai_socktype = socktype;
	hints.ai_flags    = AI_PASSIVE;

	struct addrinfo* info;
	if(getaddrinfo(NULL, port, &hints, &info) != 0)
	{
		LOGD("getaddrinfo failed");
		goto fail_getaddrinfo;
	}

	struct addrinfo* i = info;
	self->sockfd = -1;
	while(i)
	{
		self->sockfd = socket(i->ai_family, i->ai_socktype,
		                      i->ai_protocol);
		if(self->sockfd == -1)
		{
			LOGD("socket failed");
			i = i->ai_next;
			continue;
		}

		int yes = 1;
		if(setsockopt(self->sockfd, SOL_SOCKET,
		              SO_REUSEADDR, &yes,
		              sizeof(int)) == -1)
		{
			LOGD("setsockopt failed");
		}

		// TCP_NODELAY is not needed for server socket

		if(bind(self->sockfd, i->ai_addr,
		        i->ai_addrlen) == -1)
		{
			LOGD("bind failed");
			close(self->sockfd);
			self->sockfd = -1;
			continue;
		}

		break;
	}
	freeaddrinfo(info);

	if(self->sockfd == -1)
	{
		LOGD("socket failed");
		goto fail_socket;
	}

	if(listen(self->sockfd, backlog) == -1)
	{
		LOGD("listen failed");
		goto fail_listen;
	}

	self->error     = 0;
	self->connected = 1;
	self->type      = type;

	// success
	return self;

	// failure
	fail_listen:
		close(self->sockfd);
	fail_socket:
	fail_getaddrinfo:
	fail_check_priv:
	fail_use_priv:
	fail_use_cert:
	fail_cert_names:
#if NET_SOCKET_USE_OPENSSL_1_1
	fail_set_default_verify_file:
#endif
	fail_load_verify:
		SSL_CTX_free(self->ctx);
	fail_ctx:
		free(self);
	return NULL;
}

net_socketSSL_t*
net_socketSSL_accept(net_socketSSL_t* self)
{
	assert(self);

	struct sockaddr_storage info;
	socklen_t               size = sizeof(info);
	int sockfd = accept(self->sockfd,
	                    (struct sockaddr*) &info,
	                    &size);
	if(sockfd == -1)
	{
		LOGD("accept failed");
		return NULL;
	}

	net_socketSSL_t* remote;
	remote = (net_socketSSL_t*)
	         malloc(sizeof(net_socketSSL_t));
	if(remote == NULL)
	{
		LOGE("malloc failed");
		goto fail_remote;
	}

	int type = self->type;
	if(type == NET_SOCKETSSL_TCP_BUFFERED)
	{
		remote->buffer = (unsigned char*)
		                 malloc(NET_SOCKETSSL_BUFSIZE*
		                        sizeof(unsigned char));
		if(remote->buffer == NULL)
		{
			LOGE("malloc failed");
			goto fail_buffer;
		}
	}
	else
	{
		remote->buffer = NULL;
	}
	remote->len = 0;

	if((type == NET_SOCKETSSL_TCP_NODELAY) ||
	   (type == NET_SOCKETSSL_TCP_BUFFERED))
	{
		int yes = 1;
		if(setsockopt(sockfd, IPPROTO_TCP,
		              TCP_NODELAY, (const void*) &yes,
		              sizeof(int)) == -1)
		{
			LOGD("setsockopt TCP_NODELAY failed");
		}
	}

	// init SSL ctx
	remote->ctx    = self->ctx;
	remote->method = NET_SOCKETSSL_METHOD_ACCEPT;

	// init ssl
	remote->ssl = SSL_new(remote->ctx);
	if(remote->ssl == NULL)
	{
		LOGE("SSL_new failed");
		goto fail_ssl;
	}

	if(SSL_set_fd(remote->ssl, sockfd) != 1)
	{
		LOGE("SSL_set_fd failed");
		goto fail_set_fd;
	}

	int ret = SSL_accept(remote->ssl);
	if(ret != 1)
	{
		LOGE("SSL_accept failed %i",
		     SSL_get_error(self->ssl, ret));
		ERR_print_errors_fp(stderr);
		goto fail_ssl_accept;
	}

	if(SSL_get_verify_result(remote->ssl) != X509_V_OK)
	{
		LOGE("SSL_get_verify_result failed");
		goto fail_ssl_verify;
	}

	remote->sockfd    = sockfd;
	remote->error     = 0;
	remote->connected = 1;
	remote->type      = type;

	// success
	return remote;

	// failure
	fail_ssl_verify:
	fail_ssl_accept:
	fail_set_fd:
		SSL_free(remote->ssl);
	fail_ssl:
		free(remote->buffer);
	fail_buffer:
		free(remote);
	fail_remote:
		close(sockfd);
	return NULL;
}

int net_socketSSL_shutdown(net_socketSSL_t* self, int how)
{
	assert(self);

	int ret = shutdown(self->sockfd, how);
	if(ret == -1)
	{
		self->error = 1;
		LOGD("shutdown failed");
	}
	// depending on "how" we may or may not be connected
	// wait until the next recv command to set flag
	return ret;
}

void net_socketSSL_close(net_socketSSL_t** _self)
{
	// *_self can be NULL
	assert(_self);

	net_socketSSL_t* self = *_self;
	if(self)
	{
		if((self->method == NET_SOCKETSSL_METHOD_CLIENT) ||
		   (self->method == NET_SOCKETSSL_METHOD_ACCEPT))
		{
			SSL_free(self->ssl);
		}
		close(self->sockfd);
		if((self->method == NET_SOCKETSSL_METHOD_CLIENT) ||
		   (self->method == NET_SOCKETSSL_METHOD_SERVER))
		{
			SSL_CTX_free(self->ctx);
		}
		free(self->buffer);
		free(self);
		*_self = NULL;
	}
}

int net_socketSSL_keepalive(net_socketSSL_t* self,
                         int cnt, int idle, int intvl)
{
	assert(self);

	// default values take over 2 hours to reconnect
	// my recommended values take about 2 minutes to reconnect
	// cnt: max number of probes (9 -> 4)
	// idle: idle time before sending probes (7200 -> 60)
	// intvl: time between probes (75 -> 15)
	// see man 7 tcp for more details
	int enable = 1;
	if((setsockopt(self->sockfd, SOL_SOCKET, SO_KEEPALIVE,
	              &enable, sizeof(int)) == 0) &&
	   (setsockopt(self->sockfd, IPPROTO_TCP, TCP_KEEPCNT,
	              &cnt, sizeof(int)) == 0) &&
#ifndef __APPLE__
	   // TCP_KEEPIDLE is not defined on OSX
	   (setsockopt(self->sockfd, IPPROTO_TCP, TCP_KEEPIDLE,
	              &idle, sizeof(int)) == 0) &&
#endif
	   (setsockopt(self->sockfd, IPPROTO_TCP, TCP_KEEPINTVL,
	              &intvl, sizeof(int)) == 0))
	{
		return 1;
	}
	else
	{
		LOGD("keepalive failed");
		return 0;
	}
}

void net_socketSSL_timeout(net_socketSSL_t* self,
                        int recv_to, int send_to)
{
	assert(self);

	struct timeval timeout;
	timeout.tv_sec  = recv_to;
	timeout.tv_usec = 0;

	if(setsockopt(self->sockfd, SOL_SOCKET, SO_RCVTIMEO,
	              (char*) &timeout,
	              sizeof(timeout)) < 0)
	{
		LOGD("setsockopt timeout");
	}

	timeout.tv_sec = send_to;
	if(setsockopt(self->sockfd, SOL_SOCKET, SO_SNDTIMEO,
	              (char*) &timeout,
	              sizeof(timeout)) < 0)
	{
		LOGD("setsockopt timeout");
	}
}

int net_socketSSL_sendall(net_socketSSL_t* self,
                          const void* data, int len)
{
	assert(self);
	assert(data);

	int buffered = 0;
	if((self->type == NET_SOCKETSSL_TCP_BUFFERED) &&
	   (self->buffer))
	{
		buffered = 1;
	}

	return sendall(self, data, len, buffered);
}

int net_socketSSL_flush(net_socketSSL_t* self)
{
	assert(self);

	int flushed = 1;
	if((self->type == NET_SOCKETSSL_TCP_BUFFERED) &&
	   (self->buffer))
	{
		flushed = sendall(self, self->buffer, self->len, 0);
		self->len = 0;
	}
	return flushed;
}

int net_socketSSL_recv(net_socketSSL_t* self, void* data,
                       int len, int* recvd)
{
	assert(self);
	assert(data);
	assert(recvd);

	int count = SSL_read(self->ssl, data, len);
	if(count <= 0)
	{
		if(SSL_get_error(self->ssl,
		                 count) == SSL_ERROR_ZERO_RETURN)
		{
			// connection closed normally
			self->connected = 0;
		}
		else
		{
			if(self->error == 0)
			{
				LOGD("SSL_read failed");
			}
			self->error     = 1;
			self->connected = 0;
			*recvd          = 0;
			return 0;
		}
	}
	*recvd = count;
	return 1;
}

int net_socketSSL_recvall(net_socketSSL_t* self,
                          void* data, int len, int* recvd)
{
	assert(self);
	assert(data);
	assert(recvd);

	int left  = len;
	void* buf = data;
	while(left > 0)
	{
		int count = SSL_read(self->ssl, buf, left);
		if(count <= 0)
		{
			if(SSL_get_error(self->ssl,
			                 count) == SSL_ERROR_ZERO_RETURN)
			{
				if(self->connected == 1)
				{
					LOGD("SSL_read closed");
				}
			}
			else
			{
				if(self->error == 0)
				{
					LOGD("SSL_read failed");
				}
				self->error = 1;
			}
			goto fail_recv;
		}
		left = left - count;
		buf  = buf + count;
	}

	// success
	*recvd = len;
	return 1;

	// failure
	fail_recv:
		self->connected = 0;
		*recvd          = len - left;
	return 0;
}

int net_socketSSL_error(net_socketSSL_t* self)
{
	assert(self);
	return self->error;
}

int net_socketSSL_connected(net_socketSSL_t* self)
{
	assert(self);
	return self->connected;
}
