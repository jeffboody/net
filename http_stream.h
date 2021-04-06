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

#define HTTP_CONTINUE   100
#define HTTP_OK         200
#define HTTP_NO_CONTENT 204
#define HTTP_NOT_FOUND  404
#define HTTP_BUF_SIZE   4096

#define HTTP_METHOD_NONE 0
#define HTTP_METHOD_GET  1

typedef struct
{
	int status;
	int content_length;
	int chunked;
} http_response_t;

void http_response_init(http_response_t* self);

typedef struct
{
	int  method;
	int  close;
	char request[256];
} http_request_t;

void http_request_init(http_request_t* self);

typedef struct
{
	net_socket_t* sock;
	char          buf[HTTP_BUF_SIZE];
	int           size;
	int           idx;
} http_stream_t;

void http_stream_init(http_stream_t* self, net_socket_t* sock);
int  http_stream_readResponse(http_stream_t* self, http_response_t* response);
int  http_stream_readRequest(http_stream_t* self, http_request_t* request);
int  http_stream_readd(http_stream_t* self, int size, char* data);
int  http_stream_readchunked(http_stream_t* self, int* _size, char** _data);
void http_stream_writeError(http_stream_t* self, int err, const char* reason);
int  http_stream_writeData(http_stream_t* self, int size, void* data);
