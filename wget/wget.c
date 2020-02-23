/*
 * Copyright (c) 2014 Jeff Boody
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
#include <string.h>
#include <stdio.h>

#define LOG_TAG "net"
#include "libcc/cc_log.h"
#include "libcc/cc_memory.h"
#include "net/net_socket.h"
#include "net/net_socket_wget.h"

typedef struct
{
	char addr[256];
	char port[256];
	char request[256];
	char filename[256];
} http_url_t;

static const char* findc(const char* s, const char* e, char c)
{
	ASSERT(s);

	if(e)
	{
		while((*s != '\0') && (s != e))
		{
			if(*s == c)
			{
				return s;
			}
			++s;
		}
	}
	else
	{
		while(*s != '\0')
		{
			if(*s == c)
			{
				return s;
			}
			++s;
		}
	}

	return NULL;
}

static const char* findn(const char* s, char c)
{
	ASSERT(s);

	const char* p = NULL;
	while(*s != '\0')
	{
		if(*s == c)
		{
			p = s;
		}
		++s;
	}

	return p;
}

static int http_url_parse(http_url_t* self, const char* url)
{
	ASSERT(self);
	ASSERT(url);
	LOGD("debug url=%s", url);

	// http://addr:port/request
	// request = /path/filename
	// http:// is optional
	// :port is optional

	if(strlen(url) >= 256)
	{
		LOGE("invalid url=%s", url);
		return 0;
	}

	// skip http prefix
	const char* start = url;
	if(strncmp("http://", url, 7) == 0)
	{
		start = &url[7];
	}

	// addr:port
	const char* path_start = findc(start, NULL, '/');
	if(path_start == NULL)
	{
		LOGE("invalid url=%s", url);
		return 0;
	}

	int         len  = (int) (path_start - start);
	const char* port = findc(start, path_start, ':');
	if(port == NULL)
	{
		strncpy(self->addr, start, len);
		self->addr[len] = '\0';

		strcpy(self->port, "80");
	}
	else
	{
		len = (int) (port - start);
		strncpy(self->addr, start, len);
		self->addr[len] = '\0';

		++port;
		len = (int) (path_start - port);
		strncpy(self->port, port, len);
		self->port[len] = '\0';
	}

	// request
	strcpy(self->request, path_start);

	// filename
	const char* file_start = findn(path_start, '/');
	if(file_start == NULL)
	{
		LOGE("invalid url=%s", url);
		return 0;
	}
	++file_start;   // skip '/'
	strcpy(self->filename, file_start);

	if((strlen(self->addr) <= 0) ||
	   (strlen(self->port) <= 0) ||
	   (strlen(self->request) <= 0) ||
	   (strlen(self->filename) <= 0))
	{
		LOGE("invalid url=%s", url);
		LOGE("invalid addr=%s, port=%s, request=%s, filename=%s",
		     self->addr, self->port, self->request,
		     self->filename);
		return 0;
	}

	LOGD("addr     = %s", self->addr);
	LOGD("port     = %s", self->port);
	LOGD("request  = %s", self->request);
	LOGD("filename = %s", self->filename);

	return 1;
}

int main(int argc, const char** argv)
{
	if(argc != 2)
	{
		LOGE("%s url", argv[0]);
		return EXIT_FAILURE;
	}

	// parse url
	http_url_t url;
	if(http_url_parse(&url, argv[1]) == 0)
	{
		return EXIT_FAILURE;
	}

	// connect to addr
	net_socket_t* sock;
	sock = net_socket_connect(url.addr, url.port,
	                          NET_SOCKET_TCP);
	if(sock == NULL)
	{
		return EXIT_FAILURE;
	}

	// wget data
	int   size = 0;
	char* data = NULL;
	if(net_socket_wget(sock, "wget/1.0", url.request, 1,
	                   &size, (void**) &data) == 0)
	{
		LOGE("net_socket_wget failed");
		net_socket_close(&sock);
		return EXIT_FAILURE;
	}

	// save data
	FILE* f = fopen(url.filename, "w");
	if(f == NULL)
	{
		LOGE("fopen %s failed", url.filename);
		goto fail_fopen;
	}

	if(fwrite(data, size, 1, f) != 1)
	{
		LOGE("fwrite failed");
		goto fail_fwrite;
	}

	// cleanup
	fclose(f);
	FREE(data);
	net_socket_close(&sock);

	// success
	return EXIT_SUCCESS;

	// failure
	fail_fwrite:
		fclose(f);
	fail_fopen:
		FREE(data);
		net_socket_close(&sock);
	return EXIT_FAILURE;
}
