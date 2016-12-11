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

#include "net_socket.h"
#include "net_socket_wget.h"
#include "http_stream.h"
#include <stdlib.h>
#include <assert.h>
#include <stdio.h>
#include <string.h>

#define LOG_TAG "net"
#include "net_log.h"

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
		self->error = 1;
		return 0;
	}

	// read data
	if(header.chunked)
	{
		if(http_stream_readchunked(&stream, _size, (char**) _data) == 0)
		{
			goto fail_data;
		}
	}
	else
	{
		int   size = header.content_length;
		char* data = (char*) realloc(*_data, size*sizeof(char));
		if(data == NULL)
		{
			LOGE("malloc failed");
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
		free(*_data);
		*_data = NULL;
		*_size = 0;
		self->error = 1;
	return 0;
}
