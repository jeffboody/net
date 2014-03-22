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

#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <netdb.h>
#include <unistd.h>

#include "net_socket.h"
#include "net_socket_wget.h"
#include <stdlib.h>
#include <assert.h>
#include <stdio.h>
#include <string.h>
#include <ctype.h>

#define LOG_TAG "net"
#include "net_log.h"

/***********************************************************
* private                                                  *
***********************************************************/

#define HTTP_CONTINUE 100
#define HTTP_OK       200
#define HTTP_BUF_SIZE 4096

typedef struct
{
	int status;
	int content_length;
	int chunked;
} http_header_t;

static void http_header_init(http_header_t* self)
{
	assert(self);
	LOGD("debug");

	self->status         = 0;
	self->content_length = 0;
	self->chunked        = 0;
}

typedef struct
{
	net_socket_t* sock;
	char          buf[HTTP_BUF_SIZE];
	int           size;
	int           idx;
} http_stream_t;

static void http_stream_init(http_stream_t* self, net_socket_t* sock)
{
	assert(self);
	LOGD("debug");

	self->sock = sock;
	self->size = 0;
	self->idx  = 0;
}

static int http_stream_read(http_stream_t* self)
{
	assert(self);
	LOGD("debug");

	if(self->size > 0)
	{
		return 1;
	}

	int recvd = 0;
	if(net_socket_recv(self->sock, self->buf,
	                   HTTP_BUF_SIZE, &recvd) == 0)
	{
		return 0;
	}
	self->size = recvd;
	self->idx  = 0;

	return recvd ? 1 : 0;
}

static int http_stream_getc(http_stream_t* self, char* c)
{
	assert(self);
	assert(c);
	LOGD("debug");

	if(http_stream_read(self) == 0)
	{
		return 0;
	}

	*c = self->buf[self->idx];
	++self->idx;
	--self->size;
	
	return 1;
}

static int http_stream_readln(http_stream_t* self, char* line)
{
	assert(self);
	assert(line);
	LOGD("debug");

	char c;
	int  pos = 0;
	while(pos < 256)
	{
		if(http_stream_getc(self, &c) == 0)
		{
			return 0;
		}
		else if(c == '\r')
		{
			// ignore
			continue;
		}
		else if(c == '\n')
		{
			line[pos] = '\0';
			return 1;
		}

		line[pos] = c;
		++pos;
	}

	LOGE("error pos=%i", pos);
	return 0;
}

static int http_stream_readi(http_stream_t* self, int* x)
{
	assert(self);
	assert(x);
	LOGD("debug");

	char line[256];
	if(http_stream_readln(self, line) == 0)
	{
		return 0;
	}

	*x = strtol(line, NULL, 16);
	return 1;
}

static int http_stream_readh(http_stream_t* self, http_header_t* header)
{
	assert(self);
	assert(header);
	LOGD("debug");

	/*
	 * HTTP/1.1 <status> <string>
	 * CONTENT-LENGTH: <len>
	 * <optional>Transfer-Encoding: chunked
	 */

	char line[256];
	while(http_stream_readln(self, line))
	{
		int len = strnlen(line, 256);
		if(len == 0)
		{
			// endln
			if(header->status == HTTP_CONTINUE)
			{
				http_header_init(header);
				return http_stream_readh(self, header);
			}
			else if((header->status == HTTP_OK) &&
			        (header->content_length > 0))
			{
				return 1;
			}
			else if((header->status == HTTP_OK) &&
			        (header->chunked))
			{
				return 1;
			}
			else
			{
				LOGE("invalid status=%i, content_length=%i, chunked=%i",
				     header->status, header->content_length, header->chunked);
				return 0;
			}
		}

		int i;
		for(i = 0; i < len; ++i)
		{
			line[i] = (char) toupper((int) line[i]);
		}

		char s[256];
		if(sscanf(line, "HTTP/1.1 %i %s", &i, s) == 2)
		{
			header->status = i;
		}
		else if(sscanf(line, "CONTENT-LENGTH: %i", &i) == 1)
		{
			header->content_length = i;
		}
		else if(strncmp(line, "TRANSFER-ENCODING: CHUNKED", 256) == 0)
		{
			header->chunked = 1;
		}
		else
		{
			// ignore
		}
	}

	return 0;
}

static int http_stream_readd(http_stream_t* self, int size, char* data)
{
	assert(self);
	assert(data);
	LOGD("debug size=%i", size);

	while(size > 0)
	{
		if(http_stream_read(self) == 0)
		{
			return 0;
		}

		int n = (size < self->size) ? size : self->size;
		memcpy(data, &self->buf[self->idx], n);
		size       -= n;
		self->size -= n;
		data       += n;
		self->idx  += n;
	}

	return 1;
}

static int http_stream_readchunked(http_stream_t* self, int* _size, char** _data)
{
	assert(self);
	assert(_size);
	assert(_data);
	LOGD("debug");

	if((*_size != 0) || (*_data != NULL))
	{
		LOGE("invalid _size=%p, _data=%i", *_size, *_data);
		return 0;
	}

	// read data
	int   size  = 0;
	int   recvd = 0;
	char* data = NULL;
	while(1)
	{
		if(http_stream_readi(self, &size) == 0)
		{
			goto fail_chunk;
		}

		if(size == 0)
		{
			// no more chunks
			break;
		}
		else if(size < 0)
		{
			LOGE("invalid size=%i", size);
			goto fail_chunk;
		}

		char* tmp = (char*) realloc(data, recvd + size);
		if(tmp == NULL)
		{
			LOGE("realloc failed");
			goto fail_chunk;
		}
		data = tmp;

		if(http_stream_readd(self, size, &data[recvd]) == 0)
		{
			goto fail_chunk;
		}

		recvd += size;
	}

	// check if first chunk was zero length
	if(recvd == 0)
	{
		LOGE("invalid recvd=%i", recvd);
		return 0;
	}

	// read footer
	char line[256];
	while(1)
	{
		if(http_stream_readln(self, line) == 0)
		{
			goto fail_footer;
		}

		int len = strnlen(line, 256);
		if(len == 0)
		{
			// endln
			*_data = data;
			*_size = recvd;
			return 1;
		}
	}

	// failure
	fail_footer:
	fail_chunk:
		free(data);
	return 0;
}

/***********************************************************
* public                                                   *
***********************************************************/

int net_socket_wget(net_socket_t* self,
                    const char* user_agent,
                    const char* request,
                    int close,
                    int* _size, void** _data)
{
	assert(self);
	assert(user_agent);
	assert(request);
	assert(_size);
	assert(_data);
	LOGD("debug user_agent=%s, request=%s, close=%i", user_agent, request, close);

	// prepare the request
	const int REQ_SIZE = 4*256;
	char req[REQ_SIZE];
	if(close)
	{
		snprintf(req, REQ_SIZE,
		         "GET %s HTTP/1.1\n"
		         "Host: %s\n"
		         "User-Agent: %s\n"
		         "Connection: close\n\n",
		         request, self->host, user_agent);
	}
	else
	{
		snprintf(req, REQ_SIZE,
		         "GET %s HTTP/1.1\n"
		         "Host: %s\n"
		         "User-Agent: %s\n\n",
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

	// read header
	http_stream_t stream;
	http_header_t header;
	http_stream_init(&stream, self);
	http_header_init(&header);
	if(http_stream_readh(&stream, &header) == 0)
	{
		return 0;
	}

	// read data
	int   size = 0;
	char* data = NULL;
	if(header.chunked)
	{
		if(http_stream_readchunked(&stream, &size, &data) == 0)
		{
			goto fail_data;
		}
	}
	else
	{
		size = header.content_length;
		data = (char*) malloc(size*sizeof(char));
		if(data == NULL)
		{
			LOGE("malloc failed");
			return 0;
		}

		if(http_stream_readd(&stream, size, data) == 0)
		{
			goto fail_data;
		}
	}

	// success
	*_size = size;
	*_data = data;
	return 1;

	// failure
	fail_data:
		free(data);
	return 0;
}
