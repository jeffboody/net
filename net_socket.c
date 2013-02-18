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
#define LOGE(...) (net_log(__func__, __LINE__, __VA_ARGS__))

/***********************************************************
* public                                                   *
***********************************************************/

net_socket_t* net_socket_connect(const char* addr, const char* port, int type)
{
	assert(addr);
	assert(port);
	LOGD("debug addr=%s, port=%s, type=%i", addr, port, type);

	int socktype;
	if(type == NET_SOCKET_TCP)
	{
		socktype = SOCK_STREAM;
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
			i = i->ai_next;
			continue;
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

	// success
	return self;

	// failure
	fail_socket:
		close(self->sockfd);
	fail_getaddrinfo:
		free(self);
	return NULL;
}

net_socket_t* net_socket_listen(const char* port, int type, int backlog)
{
	assert(port);
	assert(backlog > 0);
	LOGD("debug port=%s, type=%i, backlog=%i", port, type, backlog);

	int socktype;
	if(type == NET_SOCKET_TCP)
	{
		socktype = SOCK_STREAM;
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
			i = i->ai_next;
			continue;
		}

		int yes = 1;
		if(setsockopt(self->sockfd, SOL_SOCKET, SO_REUSEADDR,&yes,
		              sizeof(int)) == -1)
		{
			// log and continue
			LOGE("setsockopt failed");
		}

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

	// success
	return self;

	// failure
	fail_listen:
	fail_socket:
		close(self->sockfd);
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

	remote->sockfd = sockfd;

	// success
	return remote;

	// failure
	fail_remote:
		close(sockfd);
	return NULL;
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
		free(self);
		*_self = NULL;
	}
}

int net_socket_send(net_socket_t* self, const void* data, int len)
{
	assert(self);
	LOGD("debug len=%i", len);

	return send(self->sockfd, data, len, 0);
}

int net_socket_recv(net_socket_t* self, void* data, int len)
{
	assert(self);
	LOGD("debug len=%i", len);

	return recv(self->sockfd, data, len, 0);
}