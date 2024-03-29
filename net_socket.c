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

#ifdef __APPLE__
	// for select on iOS
	#include "TargetConditionals.h"
	#if TARGET_OS_IPHONE || TARGET_IPHONE_SIMULATOR
		#include <sys/time.h>
	#endif
#endif
#ifdef NET_SOCKET_USE_SSL
	#include <openssl/err.h>
	#include <openssl/ssl.h>
	#include <openssl/x509v3.h>
#endif
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <errno.h>
#include <fcntl.h>
#include <netdb.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define LOG_TAG "net"
#include "../libcc/cc_log.h"
#include "../libcc/cc_memory.h"
#include "http_stream.h"
#include "net_socket.h"

/***********************************************************
* private                                                  *
***********************************************************/

#define NET_SOCKET_BUFSIZE 64*1024

#ifdef NET_SOCKET_USE_SSL

#define NET_SOCKETSSL_METHOD_CLIENT 0
#define NET_SOCKETSSL_METHOD_SERVER 1
#define NET_SOCKETSSL_METHOD_ACCEPT 2

typedef struct
{
	net_socket_t base;

	// SSL state
	int      method;
	SSL_CTX* ctx;
	SSL*     ssl;
} net_socketSSL_t;

static int
post_connection_check(SSL* ssl, char* host)
{
	ASSERT(ssl);
	ASSERT(host);

	// Based on Network Security with OpenSSL

	X509* cert = SSL_get_peer_certificate(ssl);
	if(cert == NULL)
	{
		LOGD("SSL_get_peer_certificate failed");
		return X509_V_ERR_APPLICATION_VERIFICATION;
	}

	X509_NAME* subj = X509_get_subject_name(cert);
	if(subj == NULL)
	{
		LOGD("X509_get_subject_name failed");
		goto fail_subj;
	}

	// get common name (CN)
	char cn[256];
	if(X509_NAME_get_text_by_NID(subj, NID_commonName,
	                             cn, 256) == -1)
	{
		LOGD("X509_NAME_get_text_by_NID failed");
		goto fail_get_cn;
	}

	// check common name (CN)
	if(strcasecmp(cn, host) != 0)
	{
		LOGD("common name failed");
		goto fail_check_cn;
	}

	if(SSL_get_verify_result(ssl) != X509_V_OK)
	{
		LOGD("SSL_get_verify_result failed");
		goto fail_verify;
	}

	X509_free(cert);

	// success
	return X509_V_OK;

	// failure
	fail_verify:
	fail_check_cn:
	fail_get_cn:
	fail_subj:
		X509_free(cert);
	return X509_V_ERR_APPLICATION_VERIFICATION;
}

#endif

static int
send_buffered(net_socket_t* self, const void* data, int len)
{
	ASSERT(self);
	ASSERT(self->buffer);
	ASSERT(data);
	// skip LOGD

	// buffer data
	int len_free = NET_SOCKET_BUFSIZE - self->len;
	int len_copy = (len_free >= len) ? len : len_free;
	void* dst = (void*) (self->buffer + self->len);
	memcpy(dst, data, len_copy);
	self->len += len_copy;

	// flush
	if(self->len == NET_SOCKET_BUFSIZE)
	{
		if(net_socket_flush(self) == 0)
		{
			return 0;
		}
	}

	return len_copy;
}

static int
sendall(net_socket_t* self, const void* data, int len,
        int flush)
{
	ASSERT(self);
	ASSERT(data);

	int left        = len;
	const void* buf = data;
	while(left > 0)
	{
		int count = 0;
		if((flush == 0) &&
		   (self->flags & NET_SOCKET_FLAG_TCP_BUFFERED))
		{
			count = send_buffered(self, buf, left);
		}
		else if(self->connected)
		{
			if((self->flags & NET_SOCKET_FLAG_SSL) == 0)
			{
				count = send(self->sockfd, buf, left, 0);
			}
			#ifdef NET_SOCKET_USE_SSL
			else
			{
				net_socketSSL_t* self_ssl = (net_socketSSL_t*) self;
				count = SSL_write(self_ssl->ssl, buf, left);
			}
			#endif
		}

		if(count <= 0)
		{
			if(self->error == 0)
			{
				LOGD("send failed");
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
net_socket_connectTimeout(net_socket_t* self,
                          net_connectInfo_t* info,
                          struct addrinfo* i)
{
	ASSERT(self);
	ASSERT(i);

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
	#ifdef NET_SOCKET_USE_SSL
	if(self->flags & NET_SOCKET_FLAG_SSL)
	{
		net_socketSSL_t* self_ssl = (net_socketSSL_t*) self;

		// init ssl
		self_ssl->ssl = SSL_new(self_ssl->ctx);
		if(self_ssl->ssl == NULL)
		{
			LOGD("SSL_new failed");
			goto fail_ssl;
		}

		if(SSL_set_fd(self_ssl->ssl, self->sockfd) != 1)
		{
			LOGD("SSL_set_fd failed");
			goto fail_set_fd;
		}

		if(SSL_connect(self_ssl->ssl) != 1)
		{
			LOGD("SSL_connect failed");
			goto fail_ssl_connect;
		}

		if((self->flags & NET_SOCKET_FLAG_SSL_CONNECT_INSECURE) == 0)
		{
			char addr[256];
			snprintf(addr, 256, "%s", info->addr);
			if(post_connection_check(self_ssl->ssl,
			                         addr) != X509_V_OK)
			{
				goto fail_ssl_verify;
			}
		}
	}
	#endif

	// success
	return 1;

	// failure
#ifdef NET_SOCKET_USE_SSL
	fail_ssl_verify:
	fail_ssl_connect:
	fail_set_fd:
	{
		net_socketSSL_t* self_ssl = (net_socketSSL_t*) self;
		if(self->flags & NET_SOCKET_FLAG_SSL)
		{
			SSL_free(self_ssl->ssl);
		}
	}
	fail_ssl:
#endif
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

net_socket_t*
net_socket_connect(net_connectInfo_t* info)
{
	ASSERT(info);

	// validate info
	size_t size     = sizeof(net_socket_t);
	int    socktype = SOCK_STREAM;
	if((info->addr == NULL) ||
	   (info->port == NULL) ||
	   (info->type < 0)     ||
	   (info->type >= NET_SOCKET_TYPE_MAX))
	{
		LOGE("invalid addr=%p, port=%p, type=%i",
		     info->addr, info->port, info->type);
		return NULL;
	}
	else if(info->flags & NET_SOCKET_FLAG_SSL)
	{
		// SSL must be enabled at compile time
		#ifdef NET_SOCKET_USE_SSL
			size = sizeof(net_socketSSL_t);

			if(info->type == NET_SOCKET_TYPE_UDP)
			{
				LOGE("invalid type=%i", info->type);
				return NULL;
			}

			if(info->flags & NET_SOCKET_FLAG_SSL_LISTEN_ANYONE)
			{
				LOGE("invalid flags=0x%X", info->flags);
				return NULL;
			}

			if((info->ca_cert == NULL) &&
			   (info->flags & NET_SOCKET_FLAG_SSL_CONNECT_INSECURE) == 0)
			{
				LOGE("invalid ca_cert=%p, flags=0x%X",
				     info->ca_cert, info->flags);
				return NULL;
			}
		#else
			LOGE("invalid flags=0x%X", info->flags);
			return NULL;
		#endif
	}
	else
	{
		if(info->type == NET_SOCKET_TYPE_UDP)
		{
			socktype = SOCK_DGRAM;
		}

		// SSL parameters requires SSL flag
		if((info->flags & NET_SOCKET_FLAG_SSL_CONNECT_INSECURE) ||
		   (info->flags & NET_SOCKET_FLAG_SSL_LISTEN_ANYONE)    ||
		   info->ca_cert || info->client_cert || info->client_key)
		{
			LOGE("invalid flags=0x%X, ca_cert=%p, client_cert=%p, client_key=%p",
			     info->flags, info->ca_cert, info->client_cert,
			     info->client_key);
		}
	}

	net_socket_t* self;
	self = (net_socket_t*) CALLOC(1, size);
	if(self == NULL)
	{
		LOGE("CALLOC failed");
		return NULL;
	}

	self->type      = info->type;
	self->flags     = info->flags;
	self->connected = 1;

	// SIGPIPE causes the process to exit for broken streams
	// but we want to receive EPIPE instead
	signal(SIGPIPE, SIG_IGN);

	if(info->flags & NET_SOCKET_FLAG_TCP_BUFFERED)
	{
		self->buffer = (unsigned char*)
		               CALLOC(NET_SOCKET_BUFSIZE,
		                      sizeof(unsigned char));
		if(self->buffer == NULL)
		{
			LOGE("CALLOC failed");
			goto fail_buffer;
		}
	}

	// for HTTP
	snprintf(self->host, 256, "%s:%s", info->addr, info->port);

	#ifdef NET_SOCKET_USE_SSL
	if(info->flags & NET_SOCKET_FLAG_SSL)
	{
		net_socketSSL_t* self_ssl = (net_socketSSL_t*) self;

		// init SSL ctx
		self_ssl->ctx = SSL_CTX_new(TLS_client_method());
		if(self_ssl->ctx == NULL)
		{
			LOGD("SSL_CTX_new failed");
			goto fail_ctx;
		}
		self_ssl->method = NET_SOCKETSSL_METHOD_CLIENT;

		if(info->ca_cert)
		{
			if(SSL_CTX_load_verify_locations(self_ssl->ctx,
			                                 info->ca_cert, NULL) != 1)
			{
				LOGD("SSL_CTX_load_verify_locations failed");
				goto fail_load_verify;
			}
		}

		if(info->client_cert)
		{
			if(SSL_CTX_use_certificate_file(self_ssl->ctx,
			                                info->client_cert,
			                                SSL_FILETYPE_PEM) != 1)
			{
				LOGD("SSL_CTX_use_certificate_file failed");
				goto fail_use_cert;
			}
		}

		if(info->client_key)
		{
			if(SSL_CTX_use_PrivateKey_file(self_ssl->ctx,
			                               info->client_key,
			                               SSL_FILETYPE_PEM) != 1)
			{
				LOGD("SSL_CTX_use_PrivateKey_file failed");
				goto fail_use_priv;
			}

			if(SSL_CTX_check_private_key(self_ssl->ctx) != 1)
			{
				LOGD("SSL_CTX_check_private_key failed");
				goto fail_check_priv;
			}
		}

		SSL_CTX_set_mode(self_ssl->ctx, SSL_MODE_AUTO_RETRY);
		if(info->flags & NET_SOCKET_FLAG_SSL_CONNECT_INSECURE)
		{
			SSL_CTX_set_verify(self_ssl->ctx,
			                   SSL_VERIFY_NONE, NULL);
		}
		else
		{
			SSL_CTX_set_verify(self_ssl->ctx,
			                   SSL_VERIFY_PEER, NULL);
		}
		SSL_CTX_set_verify_depth(self_ssl->ctx, 1);
	}
	#endif

	struct addrinfo hints;
	memset(&hints, 0, sizeof(hints));
	hints.ai_family   = AF_UNSPEC;
	hints.ai_socktype = socktype;

	struct addrinfo* ainfo;
	if(getaddrinfo(info->addr, info->port, &hints, &ainfo) != 0)
	{
		LOGD("getaddrinfo addr=%s, port=%s, failed",
		     info->addr, info->port);
		goto fail_getaddrinfo;
	}

	struct addrinfo* i = ainfo;
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

		if((info->flags & NET_SOCKET_FLAG_TCP_NODELAY) ||
		   (info->flags & NET_SOCKET_FLAG_TCP_BUFFERED))
		{
			int yes = 1;
			if(setsockopt(self->sockfd, IPPROTO_TCP, TCP_NODELAY,
			              (const void*) &yes, sizeof(int)) == -1)
			{
				LOGD("setsockopt TCP_NODELAY failed");
			}
		}

		if(net_socket_connectTimeout(self, info, i) == 0)
		{
			close(self->sockfd);
			self->sockfd = -1;
			i = i->ai_next;
			continue;
		}

		break;
	}
	freeaddrinfo(ainfo);

	if(self->sockfd == -1)
	{
		LOGD("socket failed");
		goto fail_socket;
	}

	// success
	return self;

	// failure
	fail_socket:
	fail_getaddrinfo:
#ifdef NET_SOCKET_USE_SSL
	fail_check_priv:
	fail_use_priv:
	fail_use_cert:
	fail_load_verify:
	{
		if(info->flags & NET_SOCKET_FLAG_SSL)
		{
			net_socketSSL_t* self_ssl = (net_socketSSL_t*) self;
			SSL_CTX_free(self_ssl->ctx);
		}
	}
	fail_ctx:
#endif
		FREE(self->buffer);
	fail_buffer:
		FREE(self);
	return NULL;
}

net_socket_t*
net_socket_listen(net_listenInfo_t* info)
{
	ASSERT(info);

	// validate info
	size_t size     = sizeof(net_socket_t);
	int    socktype = SOCK_STREAM;
	if((info->port == NULL) ||
	   (info->type < 0)     ||
	   (info->type >= NET_SOCKET_TYPE_MAX))
	{
		LOGE("invalid port=%p, type=%i",
		     info->port, info->type);
		return NULL;
	}
	else if(info->flags & NET_SOCKET_FLAG_SSL)
	{
		// SSL must be enabled at compile time
		#ifdef NET_SOCKET_USE_SSL
			size = sizeof(net_socketSSL_t);

			if(info->type == NET_SOCKET_TYPE_UDP)
			{
				LOGE("invalid type=%i", info->type);
				return NULL;
			}

			if(info->flags & NET_SOCKET_FLAG_SSL_CONNECT_INSECURE)
			{
				LOGE("invalid flags=0x%X", info->flags);
				return NULL;
			}

			if((info->ca_cert     == NULL) ||
			   (info->server_cert == NULL) ||
			   (info->server_key  == NULL))
			{
				LOGE("invalid ca_cert=%p, server_cert=%p, server_key=%p",
				     info->ca_cert, info->server_cert,
				     info->server_key);
				return NULL;
			}
		#else
			LOGE("invalid flags=0x%X", info->flags);
			return NULL;
		#endif
	}
	else
	{
		if(info->type == NET_SOCKET_TYPE_UDP)
		{
			socktype = SOCK_DGRAM;
		}

		// SSL parameters requires SSL flag
		if((info->flags & NET_SOCKET_FLAG_SSL_CONNECT_INSECURE) ||
		   (info->flags & NET_SOCKET_FLAG_SSL_LISTEN_ANYONE)    ||
		   info->ca_cert || info->server_cert || info->server_key)
		{
			LOGE("invalid flags=0x%X, ca_cert=%p, server_cert=%p, server_key=%p",
			     info->flags, info->ca_cert, info->server_cert,
			     info->server_key);
		}
	}

	net_socket_t* self;
	self = (net_socket_t*) CALLOC(1, size);
	if(self == NULL)
	{
		LOGE("CALLOC failed");
		return NULL;
	}

	self->type      = info->type;
	self->flags     = info->flags;
	self->connected = 1;

	// SIGPIPE causes the process to exit for broken streams
	// but we want to receive EPIPE instead
	signal(SIGPIPE, SIG_IGN);

	#ifdef NET_SOCKET_USE_SSL
	if(info->flags & NET_SOCKET_FLAG_SSL)
	{
		net_socketSSL_t* self_ssl = (net_socketSSL_t*) self;

		// init SSL ctx
		self_ssl->ctx = SSL_CTX_new(TLS_server_method());
		if(self_ssl->ctx == NULL)
		{
			LOGD("SSL_CTX_new failed");
			goto fail_ctx;
		}
		self_ssl->method = NET_SOCKETSSL_METHOD_SERVER;
		self_ssl->ssl    = NULL;

		if(SSL_CTX_load_verify_locations(self_ssl->ctx,
		                                 info->ca_cert,
		                                 NULL) != 1)
		{
			LOGD("SSL_CTX_load_verify_locations failed");
			goto fail_load_verify;
		}

		STACK_OF(X509_NAME)* cert_names;
		cert_names = SSL_load_client_CA_file(info->ca_cert);
		if(cert_names == NULL)
		{
			LOGD("SSL_load_client_CA_file failed");
			goto fail_cert_names;
		}
		SSL_CTX_set_client_CA_list(self_ssl->ctx, cert_names);

		if(SSL_CTX_use_certificate_file(self_ssl->ctx,
		                                info->server_cert,
		                                SSL_FILETYPE_PEM) != 1)
		{
			LOGD("SSL_CTX_use_certificate_file failed");
			goto fail_use_cert;
		}

		if(SSL_CTX_use_PrivateKey_file(self_ssl->ctx,
		                               info->server_key,
		                               SSL_FILETYPE_PEM) != 1)
		{
			LOGD("SSL_CTX_use_PrivateKey_file failed");
			goto fail_use_priv;
		}

		if(SSL_CTX_check_private_key(self_ssl->ctx) != 1)
		{
			LOGD("SSL_CTX_check_private_key failed");
			goto fail_check_priv;
		}

		SSL_CTX_set_mode(self_ssl->ctx, SSL_MODE_AUTO_RETRY);
		if(self->flags & NET_SOCKET_FLAG_SSL_LISTEN_ANYONE)
		{
			SSL_CTX_set_verify(self_ssl->ctx,
			                   SSL_VERIFY_NONE, NULL);
		}
		else
		{
			SSL_CTX_set_verify(self_ssl->ctx,
			                   SSL_VERIFY_PEER |
			                   SSL_VERIFY_FAIL_IF_NO_PEER_CERT,
			                   NULL);
		}
		SSL_CTX_set_verify_depth(self_ssl->ctx, 1);
	}
	#endif

	struct addrinfo hints;
	memset(&hints, 0, sizeof(hints));
	hints.ai_family   = AF_UNSPEC;
	hints.ai_socktype = socktype;
	hints.ai_flags    = AI_PASSIVE;

	struct addrinfo* ainfo;
	if(getaddrinfo(NULL, info->port, &hints, &ainfo) != 0)
	{
		LOGD("getaddrinfo failed");
		goto fail_getaddrinfo;
	}

	struct addrinfo* i = ainfo;
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
		if(setsockopt(self->sockfd, SOL_SOCKET, SO_REUSEADDR,
		              &yes, sizeof(int)) == -1)
		{
			LOGD("setsockopt failed");
		}

		// TCP_NODELAY is not needed for server socket

		if(bind(self->sockfd, i->ai_addr, i->ai_addrlen) == -1)
		{
			LOGD("bind failed");
			close(self->sockfd);
			self->sockfd = -1;
			continue;
		}

		break;
	}
	freeaddrinfo(ainfo);

	if(self->sockfd == -1)
	{
		LOGD("socket failed");
		goto fail_socket;
	}

	if(listen(self->sockfd, SOMAXCONN) == -1)
	{
		LOGD("listen failed");
		goto fail_listen;
	}

	// success
	return self;

	// failure
	fail_listen:
		close(self->sockfd);
	fail_socket:
	fail_getaddrinfo:
#ifdef NET_SOCKET_USE_SSL
	fail_check_priv:
	fail_use_priv:
	fail_use_cert:
	fail_cert_names:
	fail_load_verify:
	{
		net_socketSSL_t* self_ssl = (net_socketSSL_t*) self;
		if(info->flags & NET_SOCKET_FLAG_SSL)
		{
			SSL_CTX_free(self_ssl->ctx);
		}
	}
	fail_ctx:
#endif
		FREE(self);
	return NULL;
}

net_socket_t* net_socket_accept(net_socket_t* self)
{
	ASSERT(self);

	size_t size = sizeof(net_socket_t);
	if(self->flags & NET_SOCKET_FLAG_SSL)
	{
		#ifdef NET_SOCKET_USE_SSL
			size = sizeof(net_socketSSL_t);
		#else
			LOGE("invalid flags=0x%X", self->flags);
			return NULL;
		#endif
	}

	struct sockaddr_storage info;
	socklen_t               addrlen = sizeof(info);
	int sockfd = accept(self->sockfd,
	                    (struct sockaddr*) &info, &addrlen);
	if(sockfd == -1)
	{
		LOGD("accept failed");
		return NULL;
	}

	net_socket_t* remote;
	remote = (net_socket_t*) CALLOC(1, size);
	if(remote == NULL)
	{
		LOGE("CALLOC failed");
		goto fail_remote;
	}

	remote->type      = self->type;
	remote->flags     = self->flags;
	remote->sockfd    = sockfd;
	remote->connected = 1;

	if(self->flags & NET_SOCKET_FLAG_TCP_BUFFERED)
	{
		remote->buffer = (unsigned char*)
		                 CALLOC(NET_SOCKET_BUFSIZE,
		                        sizeof(unsigned char));
		if(remote->buffer == NULL)
		{
			LOGE("CALLOC failed");
			goto fail_buffer;
		}
	}

	if((self->flags & NET_SOCKET_FLAG_TCP_NODELAY) ||
	   (self->flags & NET_SOCKET_FLAG_TCP_BUFFERED))
	{
		int yes = 1;
		if(setsockopt(sockfd, IPPROTO_TCP, TCP_NODELAY,
		              (const void*) &yes, sizeof(int)) == -1)
		{
			LOGD("setsockopt TCP_NODELAY failed");
		}
	}

	#ifdef NET_SOCKET_USE_SSL
	if(self->flags & NET_SOCKET_FLAG_SSL)
	{
		net_socketSSL_t* self_ssl   = (net_socketSSL_t*) self;
		net_socketSSL_t* remote_ssl = (net_socketSSL_t*) remote;

		// init SSL ctx
		remote_ssl->ctx    = self_ssl->ctx;
		remote_ssl->method = NET_SOCKETSSL_METHOD_ACCEPT;

		// set timeout for SSL handshake
		net_socket_timeout(remote, 4, 4);

		// init ssl
		remote_ssl->ssl = SSL_new(remote_ssl->ctx);
		if(remote_ssl->ssl == NULL)
		{
			LOGD("SSL_new failed");
			goto fail_ssl;
		}

		if(SSL_set_fd(remote_ssl->ssl, sockfd) != 1)
		{
			LOGD("SSL_set_fd failed");
			goto fail_set_fd;
		}

		int ret = SSL_accept(remote_ssl->ssl);
		if(ret != 1)
		{
			LOGD("SSL_accept failed %i",
			     SSL_get_error(remote_ssl->ssl, ret));
			#ifdef LOG_DEBUG
				ERR_print_errors_fp(stderr);
			#endif
			goto fail_ssl_accept;
		}

		if((remote->flags & NET_SOCKET_FLAG_SSL_LISTEN_ANYONE) == 0)
		{
			// Per Network Security with OpenSSL
			// post_connection_check can also be used here however
			// the client FQDN (fully qualified domain name) may not
			// be readily available and must use the IP address to
			// discover the FQDN
			if(SSL_get_verify_result(remote_ssl->ssl) != X509_V_OK)
			{
				LOGD("SSL_get_verify_result failed");
				goto fail_ssl_verify;
			}
		}

		// restore default timeout
		net_socket_timeout(remote, 0, 0);
	}
	#endif

	// success
	return remote;

	// failure
#ifdef NET_SOCKET_USE_SSL
	fail_ssl_verify:
	fail_ssl_accept:
	fail_set_fd:
	{
		if(self->flags & NET_SOCKET_FLAG_SSL)
		{
			net_socketSSL_t* remote_ssl;
			remote_ssl = (net_socketSSL_t*) remote;
			SSL_free(remote_ssl->ssl);
		}
	}
	fail_ssl:
		FREE(remote->buffer);
#endif
	fail_buffer:
		FREE(remote);
	fail_remote:
		close(sockfd);
	return NULL;
}

int net_socket_shutdown(net_socket_t* self, int how)
{
	ASSERT(self);

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

void net_socket_close(net_socket_t** _self)
{
	// *_self can be NULL
	ASSERT(_self);

	net_socket_t* self = *_self;
	if(self)
	{
		if((self->flags & NET_SOCKET_FLAG_SSL) == 0)
		{
			close(self->sockfd);
		}
		#ifdef NET_SOCKET_USE_SSL
		else
		{
			net_socketSSL_t* self_ssl = (net_socketSSL_t*) self;
			if((self_ssl->method == NET_SOCKETSSL_METHOD_CLIENT) ||
			   (self_ssl->method == NET_SOCKETSSL_METHOD_ACCEPT))
			{
				SSL_free(self_ssl->ssl);
			}
			close(self->sockfd);
			if((self_ssl->method == NET_SOCKETSSL_METHOD_CLIENT) ||
			   (self_ssl->method == NET_SOCKETSSL_METHOD_SERVER))
			{
				SSL_CTX_free(self_ssl->ctx);
			}
		}
		#endif
		FREE(self->buffer);
		FREE(self);
		*_self = NULL;
	}
}

int net_socket_keepalive(net_socket_t* self, int cnt,
                         int idle, int intvl)
{
	ASSERT(self);

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

void net_socket_timeout(net_socket_t* self,
                        int recv_to, int send_to)
{
	ASSERT(self);

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

int net_socket_sendall(net_socket_t* self,
                       const void* data, int len)
{
	ASSERT(self);
	ASSERT(data);

	return sendall(self, data, len, 0);
}

int net_socket_flush(net_socket_t* self)
{
	ASSERT(self);

	int flushed = 1;
	if(self->flags & NET_SOCKET_FLAG_TCP_BUFFERED)
	{
		flushed = sendall(self, self->buffer, self->len, 1);
		self->len = 0;
	}
	return flushed;
}

int net_socket_recv(net_socket_t* self, void* data,
                    int len, int* _recvd)
{
	ASSERT(self);
	ASSERT(data);
	ASSERT(_recvd);

	*_recvd = 0;

	int recvd = 0;
	if((self->flags & NET_SOCKET_FLAG_SSL) == 0)
	{
		recvd = recv(self->sockfd, data, len, 0);
		if(recvd == -1)
		{
			if(self->error == 0)
			{
				LOGD("recv failed");
			}
			self->error     = 1;
			self->connected = 0;
			return 0;
		}
		else if(recvd == 0)
		{
			// connection closed normally
			self->connected = 0;
		}
	}
	#ifdef NET_SOCKET_USE_SSL
	else
	{
		net_socketSSL_t* self_ssl = (net_socketSSL_t*) self;
		recvd = SSL_read(self_ssl->ssl, data, len);
		if(recvd <= 0)
		{
			if(SSL_get_error(self_ssl->ssl,
			                 recvd) == SSL_ERROR_ZERO_RETURN)
			{
				// connection closed normally
				self->connected = 0;
				recvd           = 0;
			}
			else
			{
				if(self->error == 0)
				{
					LOGD("SSL_read failed");
				}
				self->error     = 1;
				self->connected = 0;
				return 0;
			}
		}
	}
	#endif
	*_recvd = recvd;
	return 1;
}

int net_socket_recvall(net_socket_t* self, void* data,
                       int len, int* _recvd)
{
	ASSERT(self);
	ASSERT(data);
	ASSERT(_recvd);

	*_recvd = 0;

	int   recvd = 0;
	int   left  = len;
	void* buf   = data;
	while(left > 0)
	{
		if(net_socket_recv(self, buf, left, &recvd) == 0)
		{
			goto fail_recv;
		}
		left     = left - recvd;
		buf      = buf + recvd;
		*_recvd += recvd;
	}

	// success
	return 1;

	// failure
	fail_recv:
		self->connected = 0;
		*_recvd         = len - left;
	return 0;
}

int net_socket_error(net_socket_t* self)
{
	ASSERT(self);
	return self->error;
}

int net_socket_connected(net_socket_t* self)
{
	ASSERT(self);
	return self->connected;
}

int net_socket_wget(net_socket_t* self,
                    const char* user_agent,
                    const char* request, int close,
                    int* _status, int* _size,
                    void** _data)
{
	ASSERT(self);
	ASSERT(user_agent);
	ASSERT(request);
	ASSERT(_status);
	ASSERT(_size);
	ASSERT(_data);

	// initialize state
	*_status = 0;
	*_size   = 0;

	// prepare the request
	const int REQ_SIZE = 4*256;
	char req[REQ_SIZE];
	if(close)
	{
		snprintf(req, REQ_SIZE,
		         "GET %s HTTP/1.1\r\n"
		         "Host: %s\r\n"
		         "User-Agent: %s\r\n"
		         "Connection: close\r\n\r\n",
		         request, self->host, user_agent);
	}
	else
	{
		snprintf(req, REQ_SIZE,
		         "GET %s HTTP/1.1\r\n"
		         "Host: %s\r\n"
		         "User-Agent: %s\r\n\r\n",
		         request, self->host, user_agent);
	}

	// send the GET request
	int len = strnlen(req, REQ_SIZE);
	if(net_socket_sendall(self, (const void*) req, len) == 0)
	{
		return 0;
	}

	// flush the socket in case it is buffered
	if(net_socket_flush(self) == 0)
	{
		return 0;
	}

	// read response
	http_stream_t   stream;
	http_response_t response;
	http_stream_init(&stream, self);
	http_response_init(&response);
	if(http_stream_readResponse(&stream, &response) == 0)
	{
		*_status = response.status;

		// don't set the error flag if not found
		// TODO - redesign sockets to handle status codes better
		if(response.status != HTTP_NOT_FOUND)
		{
			self->error = 1;
		}
		return 0;
	}
	else
	{
		*_status = response.status;
	}

	// read data
	if(response.chunked)
	{
		if(http_stream_readchunked(&stream, _size,
		                           (char**) _data) == 0)
		{
			goto fail_data;
		}
	}
	else if(response.content_length)
	{
		int   size = response.content_length;
		char* data = (char*) REALLOC(*_data, size*sizeof(char));
		if(data == NULL)
		{
			LOGE("REALLOC failed");
			self->error = 1;
			return 0;
		}
		*_data = data;
		*_size = size;

		if(http_stream_readd(&stream, size, data) == 0)
		{
			goto fail_data;
		}
	}

	// success
	return 1;

	// failure
	fail_data:
		FREE(*_data);
		*_data = NULL;
		*_size = 0;
		self->error = 1;
	return 0;
}

int net_socket_wserve(net_socket_t* self,
                      int tid, int chunked,
                      void* request_priv,
                      net_socket_requestFn request_fn,
                      int* close)
{
	ASSERT(self);
	ASSERT(request_fn);
	ASSERT(close);

	if(chunked)
	{
		LOGW("chunked not supported");
	}

	http_request_t request;
	http_request_init(&request);

	http_stream_t stream;
	http_stream_init(&stream, self);

	// read the request
	if(http_stream_readRequest(&stream, &request) == 0)
	{
		self->error = 1;
		return 0;
	}

	// get the request data
	int   size = 0;
	char* data = NULL;
	if((*request_fn)(tid, request_priv,
	                 request.request,
	                 &size, (void**) &data) == 0)
	{
		goto fail_data;
	}

	if(size == 0)
	{
		http_stream_writeError(&stream, HTTP_NO_CONTENT,
		                       "No content");
	}
	else if(http_stream_writeData(&stream, size, (void*) data) == 0)
	{
		// don't call writeError
		self->error = 1;
		FREE(data);
		return 0;
	}

	FREE(data);

	// hint to keep socket alive
	*close = request.close;

	// success
	return 1;

	// failure
	fail_data:
		FREE(data);
		// don't set the error flag if not found
		// TODO - redesign sockets to handle status codes better
		http_stream_writeError(&stream, HTTP_NOT_FOUND,
		                       "Not found");
	return 0;
}

int net_socket_requestFile(int tid, void* request_priv,
                           const char* request,
                           int* _size, void** _data)
{
	ASSERT(request_priv == NULL);
	ASSERT(request);
	ASSERT(_size);
	ASSERT(_data);

	*_data = NULL;
	*_size = 0;

	// remove the leading '/'
	const char* fname = &(request[1]);

	FILE* f = fopen(fname, "r");
	if(f == NULL)
	{
		LOGE("fopen failed fname=%s", fname);
		return 0;
	}

	// determine file size
	fseek(f, (long) 0, SEEK_END);
	int size = (int) ftell(f);
	fseek(f, 0, SEEK_SET);

	char* data = (char*) MALLOC(size*sizeof(char));
	if(data == NULL)
	{
		LOGE("MALLOC failed");
		goto fail_malloc;
	}

	if(fread(data, size, 1, f) != 1)
	{
		LOGE("fread failed");
		goto fail_fread;
	}

	fclose(f);

	*_data = data;
	*_size = size;

	// success
	return 1;

	// failure
	fail_fread:
		FREE(data);
	fail_malloc:
		fclose(f);
	return 0;
}
