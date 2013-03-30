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

#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <netdb.h>
#include <unistd.h>

#include "net_socket.h"
#include <stdlib.h>
#include <assert.h>

/***********************************************************
* private - log api                                        *
***********************************************************/

#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <assert.h>
#include <stdarg.h>

#ifdef ANDROID
	#include <android/log.h>
#endif

static void net_log(const char* func, int line, const char* fmt, ...)
{
	assert(func);
	assert(fmt);

	char buf[256];
	snprintf(buf, 256, "%s@%i ", func, line);

	int size = (int) strlen(buf);
	if(size < 256)
	{
		va_list argptr;
		va_start(argptr, fmt);
		vsnprintf(&buf[size], 256 - size, fmt, argptr);
		va_end(argptr);
	}
	#ifdef ANDROID
		__android_log_print(ANDROID_LOG_INFO, "net", buf);
	#else
		printf("%s\n", buf);
	#endif
}

#ifdef LOG_DEBUG
	#define LOGD(...) (net_log(__func__, __LINE__, __VA_ARGS__))
#else
	#define LOGD(...)
#endif
#define LOGI(...) (net_log(__func__, __LINE__, __VA_ARGS__))
#define LOGW(...) (net_log(__func__, __LINE__, __VA_ARGS__))
#define LOGE(...) (net_log(__func__, __LINE__, __VA_ARGS__))

/***********************************************************
* private                                                  *
***********************************************************/

#define NET_SOCKET_BUFSIZE 64*1024

static int send_buffered(net_socket_t* self, const void* data, int len)
{
	assert(self);
	assert(self->buffer);
	assert(data);
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

static int sendall(net_socket_t* self, const void* data, int len, int buffered)
{
	assert(self);
	assert(data);
	LOGD("debug len=%i, buffered=%i", len, buffered);

	int left        = len;
	const void* buf = data;
	while(left > 0)
	{
		int count;
		if(buffered)
		{
			count = send_buffered(self, buf, left);
		}
		else
		{
			count = send(self->sockfd, buf, left, 0);
		}

		if(count <= 0)
		{
			LOGE("send failed");
			self->error     = 1;
			self->connected = 0;
			return 0;
		}
		left = left - count;
		buf  = buf + count;
	}
	return 1;
}

/***********************************************************
* public                                                   *
***********************************************************/

net_socket_t* net_socket_connect(const char* addr, const char* port, int type)
{
	assert(addr);
	assert(port);
	LOGD("debug addr=%s, port=%s, type=%i", addr, port, type);

	int socktype;
	if((type >= NET_SOCKET_TCP) &&
	   (type < NET_SOCKET_UDP))
	{
		socktype = SOCK_STREAM;
	}
	else if(type == NET_SOCKET_UDP)
	{
		socktype = SOCK_DGRAM;
	}
	else
	{
		LOGE("invalid type=%i", type);
		return NULL;
	}

	net_socket_t* self = (net_socket_t*) malloc(sizeof(net_socket_t));
	if(self == NULL)
	{
		LOGE("malloc failed");
		return NULL;
	}

	if(type == NET_SOCKET_TCP_BUFFERED)
	{
		self->buffer = (unsigned char*) malloc(NET_SOCKET_BUFSIZE*sizeof(unsigned char));
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

	struct addrinfo hints;
	memset(&hints, 0, sizeof(hints));
	hints.ai_family   = AF_UNSPEC;
	hints.ai_socktype = socktype;

	struct addrinfo* info;
	if(getaddrinfo(addr, port, &hints, &info) != 0)
	{
		LOGE("getaddrinfo failed");
		goto fail_getaddrinfo;
	}

	struct addrinfo* i = info;
	self->sockfd = -1;
	while(i)
	{
		self->sockfd = socket(i->ai_family, i->ai_socktype, i->ai_protocol);
		if(self->sockfd == -1)
		{
			LOGE("socket failed");
			i = i->ai_next;
			continue;
		}

		if((type == NET_SOCKET_TCP_NODELAY) ||
		   (type == NET_SOCKET_TCP_BUFFERED))
		{
			int yes = 1;
			if(setsockopt(self->sockfd, IPPROTO_TCP, TCP_NODELAY, (const void*) &yes,
			              sizeof(int)) == -1)
			{
				LOGW("setsockopt TCP_NODELAY failed");
			}
		}

		if(connect(self->sockfd, i->ai_addr, i->ai_addrlen) == -1)
		{
			LOGE("connect failed");
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
		LOGE("socket failed");
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
		free(self->buffer);
	fail_buffer:
		free(self);
	return NULL;
}

net_socket_t* net_socket_listen(const char* port, int type, int backlog)
{
	assert(port);
	assert(backlog > 0);
	LOGD("debug port=%s, type=%i, backlog=%i", port, type, backlog);

	int socktype;
	if((type >= NET_SOCKET_TCP) &&
	   (type < NET_SOCKET_UDP))
	{
		socktype = SOCK_STREAM;
	}
	else if(type == NET_SOCKET_UDP)
	{
		socktype = SOCK_DGRAM;
	}
	else
	{
		LOGE("invalid type=%i", type);
		return NULL;
	}

	net_socket_t* self = (net_socket_t*) malloc(sizeof(net_socket_t));
	if(self == NULL)
	{
		LOGE("malloc failed");
		return NULL;
	}

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
		LOGE("getaddrinfo failed");
		goto fail_getaddrinfo;
	}

	struct addrinfo* i = info;
	self->sockfd = -1;
	while(i)
	{
		self->sockfd = socket(i->ai_family, i->ai_socktype, i->ai_protocol);
		if(self->sockfd == -1)
		{
			LOGE("socket failed");
			i = i->ai_next;
			continue;
		}

		int yes = 1;
		if(setsockopt(self->sockfd, SOL_SOCKET, SO_REUSEADDR, &yes,
		              sizeof(int)) == -1)
		{
			LOGW("setsockopt failed");
		}

		// TCP_NODELAY is not needed for server socket

		if(bind(self->sockfd, i->ai_addr, i->ai_addrlen) == -1)
		{
			LOGE("bind failed");
			close(self->sockfd);
			self->sockfd = -1;
			continue;
		}

		break;
	}
	freeaddrinfo(info);

	if(self->sockfd == -1)
	{
		LOGE("socket failed");
		goto fail_socket;
	}

	if(listen(self->sockfd, backlog) == -1)
	{
		LOGE("listen failed");
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
		free(self);
	return NULL;
}

net_socket_t* net_socket_accept(net_socket_t* self)
{
	assert(self);
	LOGD("debug");

	struct sockaddr_storage info;
	socklen_t               size = sizeof(info);
	int sockfd = accept(self->sockfd, (struct sockaddr*) &info, &size);
	if(sockfd == -1)
	{
		LOGE("accept failed");
		return NULL;
	}

	net_socket_t* remote = (net_socket_t*) malloc(sizeof(net_socket_t));
	if(remote == NULL)
	{
		LOGE("malloc failed");
		goto fail_remote;
	}

	int type = self->type;
	if(type == NET_SOCKET_TCP_BUFFERED)
	{
		remote->buffer = (unsigned char*) malloc(NET_SOCKET_BUFSIZE*sizeof(unsigned char));
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

	if((type == NET_SOCKET_TCP_NODELAY) ||
	   (type == NET_SOCKET_TCP_BUFFERED))
	{
		int yes = 1;
		if(setsockopt(sockfd, IPPROTO_TCP, TCP_NODELAY, (const void*) &yes,
		              sizeof(int)) == -1)
		{
			LOGW("setsockopt TCP_NODELAY failed");
		}
	}

	remote->sockfd    = sockfd;
	remote->error     = 0;
	remote->connected = 1;
	remote->type      = type;

	// success
	return remote;

	// failure
	fail_buffer:
		free(remote);
	fail_remote:
		close(sockfd);
	return NULL;
}

int net_socket_shutdown(net_socket_t* self, int how)
{
	assert(self);
	LOGD("debug how=%i", how);

	int ret = shutdown(self->sockfd, how);
	if(ret == -1)
	{
		self->error = 1;
		LOGE("shutdown failed");
	}
	// depending on "how" we may or may not be connected
	// wait until the next recv command to set flag
	return ret;
}

void net_socket_close(net_socket_t** _self)
{
	// *_self can be NULL
	assert(_self);

	net_socket_t* self = *_self;
	if(self)
	{
		LOGD("debug");
		close(self->sockfd);
		free(self->buffer);
		free(self);
		*_self = NULL;
	}
}

int net_socket_sendall(net_socket_t* self, const void* data, int len)
{
	assert(self);
	assert(data);
	LOGD("debug len=%i", len);

	int buffered = 0;
	if((self->type == NET_SOCKET_TCP_BUFFERED) &&
	   (self->buffer))
	{
		buffered = 1;
	}

	return sendall(self, data, len, buffered);
}

int net_socket_flush(net_socket_t* self)
{
	assert(self);
	LOGD("debug");

	int flushed = 1;
	if((self->type == NET_SOCKET_TCP_BUFFERED) &&
	   (self->buffer))
	{
		flushed = sendall(self, self->buffer, self->len, 0);
		self->len = 0;
	}
	return flushed;
}

int net_socket_recv(net_socket_t* self, void* data, int len, int* recvd)
{
	assert(self);
	assert(data);
	assert(recvd);
	LOGD("debug len=%i", len);

	int count = recv(self->sockfd, data, len, 0);
	if(count == -1)
	{
		LOGE("recv failed");
		self->error     = 1;
		self->connected = 0;
		*recvd          = 0;
		return 0;
	}
	else if(count == 0)
	{
		// connection closed normally
		self->connected = 0;
	}
	*recvd = count;
	return 1;
}

int net_socket_recvall(net_socket_t* self, void* data, int len, int* recvd)
{
	assert(self);
	assert(data);
	assert(recvd);
	LOGD("debug len=%i", len);

	int left  = len;
	void* buf = data;
	while(left > 0)
	{
		int count = recv(self->sockfd, buf, left, 0);
		if(count == -1)
		{
			LOGE("recv failed");
			self->error = 1;
			goto fail_recv;
		}
		else if(count == 0)
		{
			LOGE("recv closed");
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

int net_socket_error(net_socket_t* self)
{
	assert(self);
	LOGD("debug");
	return self->error;
}

int net_socket_connected(net_socket_t* self)
{
	assert(self);
	LOGD("debug");
	return self->connected;
}
