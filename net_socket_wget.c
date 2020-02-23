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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define LOG_TAG "net"
#include "../libcc/cc_log.h"
#include "../libcc/cc_memory.h"
#include "http_stream.h"
#include "net_socket.h"
#include "net_socket_wget.h"

/***********************************************************
* public                                                   *
***********************************************************/

int net_socket_wget(net_socket_t* self,
                    const char* user_agent,
                    const char* request, int close,
                    int* _size, void** _data)
{
	ASSERT(self);
	ASSERT(user_agent);
	ASSERT(request);
	ASSERT(_size);
	ASSERT(_data);

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
		// don't set the error flag if not found
		// TODO - redesign sockets to handle status codes better
		if(response.status != HTTP_NOT_FOUND)
		{
			self->error = 1;
		}
		return 0;
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
	else
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

int net_socket_wserve(net_socket_t* self, int chunked,
                      void* request_priv,
                      net_socket_request_fn request_fn,
                      int* close)
{
	// request_fn may be NULL
	ASSERT(self);
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
	int   ok;
	int   size = 0;
	char* data = NULL;
	if(request_fn)
	{
		ok = (*request_fn)(request_priv, request.request,
		                   &size, (void**) &data);
	}
	else
	{
		ok = net_socket_requestFile(NULL, request.request,
		                            &size, (void**) &data);
	}

	if(ok == 0)
	{
		goto fail_data;
	}

	if(http_stream_writeData(&stream, size, (void*) data) == 0)
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

int net_socket_requestFile(void* priv, const char* request,
                           int* _size, void** _data)
{
	ASSERT(priv == NULL);
	ASSERT(request);
	ASSERT(_size);
	ASSERT(_data);

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
	*_size = size;

	char* data = (char*) REALLOC(*_data, size*sizeof(char));
	if(data == NULL)
	{
		LOGE("REALLOC failed");
		goto fail_realloc;
	}
	*_data = data;

	if(fread(data, size, 1, f) != 1)
	{
		LOGE("fread failed");
		goto fail_fread;
	}

	fclose(f);

	// success
	return 1;

	// failure
	fail_fread:
	fail_realloc:
		fclose(f);
	return 0;
}
