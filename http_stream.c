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

#include "http_stream.h"
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

	LOGD("error pos=%i", pos);
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

static int http_request_validate(const char* s)
{
	assert(s);

	// require leading '/'
	if(s[0] != '/')
	{
		LOGD("invalid request=%s", s);
		return 0;
	}

	int i = 0;
	while(s[i] != '\0')
	{
		// restrict the supported characters
		if(((s[i] >= 'a') && (s[i]     <= 'z')) ||
		   ((s[i] >= 'A') && (s[i]     <= 'Z')) ||
		   ((s[i] >= '0') && (s[i]     <= '9')) ||
		   ((s[i] == '.') && (s[i + 1] != '.')) ||
		   (s[i] == '_') ||
		   (s[i] == '-') ||
		   (s[i] == '+') ||
		   (s[i] == '/'))
		{
			++i;
			continue;
		}

		LOGD("invalid request=%s", s);
		return 0;
	}

	return 1;
}

/***********************************************************
* public                                                   *
***********************************************************/

void http_response_init(http_response_t* self)
{
	assert(self);
	LOGD("debug");

	self->status         = 0;
	self->content_length = 0;
	self->chunked        = 0;
}

void http_request_init(http_request_t* self)
{
	assert(self);
	LOGD("debug");

	self->method = HTTP_METHOD_NONE;
	self->close  = 0;

	snprintf(self->request, 256, "%s", "");
	self->request[255] = '\0';
}

void http_stream_init(http_stream_t* self, net_socket_t* sock)
{
	assert(self);
	LOGD("debug");

	self->sock = sock;
	self->size = 0;
	self->idx  = 0;
}

int http_stream_readResponse(http_stream_t* self,
                             http_response_t* response)
{
	assert(self);
	assert(response);
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
			if(response->status == HTTP_CONTINUE)
			{
				http_response_init(response);
				return http_stream_readResponse(self, response);
			}
			else if((response->status == HTTP_OK) &&
			        (response->content_length > 0))
			{
				return 1;
			}
			else if((response->status == HTTP_OK) &&
			        (response->chunked))
			{
				return 1;
			}
			else
			{
				LOGD("invalid status=%i, content_length=%i, chunked=%i",
				     response->status, response->content_length, response->chunked);
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
			response->status = i;
		}
		else if(sscanf(line, "CONTENT-LENGTH: %i", &i) == 1)
		{
			response->content_length = i;
		}
		else if(strncmp(line, "TRANSFER-ENCODING: CHUNKED", 256) == 0)
		{
			response->chunked = 1;
		}
		else
		{
			// ignore
		}
	}

	LOGD("invalid response");
	return 0;
}

int http_stream_readRequest(http_stream_t* self, http_request_t* request)
{
	assert(self);
	assert(request);
	LOGD("debug");

	/*
	 * GET <request> HTTP/1.1
	 * <optional>Connection: close
	 */

	char line[256];
	while(http_stream_readln(self, line))
	{
		int len = strnlen(line, 256);
		if(len == 0)
		{
			// endln
			if(request->method == HTTP_METHOD_GET)
			{
				return 1;
			}
			else
			{
				LOGD("invalid method=%i, close=%i, request=%s",
				     request->method, request->close, request->request);
				return 0;
			}
		}

		int i;
		char uline[256];
		strncpy(uline, line, 256);
		uline[255] = '\0';
		for(i = 0; i < len; ++i)
		{
			uline[i] = (char) toupper((int) uline[i]);
		}

		char s[256];
		if(sscanf(uline, "GET %s HTTP/1.1", s) == 1)
		{
			if(request->method == HTTP_METHOD_GET)
			{
				LOGD("invalid line=%s", line);
				return 0;
			}

			// rescan case sensitive request
			char s1[256];
			char s2[256];
			char s3[256];
			if(sscanf(line, "%s %s %s", s1, s2, s3) == 3)
			{
				if(http_request_validate(s2))
				{
					strncpy(request->request, s2, 256);
					request->request[255] = '\0';
					request->method = HTTP_METHOD_GET;
				}
			}
			else
			{
				LOGD("invalid line=%s", line);
				return 0;
			}
		}
		else if(strncmp(uline, "CONNECTION: CLOSE", 256) == 0)
		{
			request->close = 1;
		}
		else
		{
			// ignore
		}
	}

	LOGD("invalid request");
	return 0;
}

int http_stream_readd(http_stream_t* self, int size, char* data)
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

int http_stream_readchunked(http_stream_t* self, int* _size, char** _data)
{
	assert(self);
	assert(_size);
	assert(_data);
	LOGD("debug");

	// read data
	int   size  = 0;
	int   recvd = 0;
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
			LOGD("invalid size=%i", size);
			goto fail_chunk;
		}

		char* data = (char*) realloc(*_data, recvd + size);
		if(data == NULL)
		{
			LOGE("realloc failed");
			goto fail_chunk;
		}
		*_data = data;
		*_size = recvd + size;

		if(http_stream_readd(self, size, &data[recvd]) == 0)
		{
			goto fail_chunk;
		}

		recvd += size;
	}

	// check if first chunk was zero length
	if(recvd == 0)
	{
		LOGD("invalid recvd=%i", recvd);
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
			return 1;
		}
	}

	// failure
	fail_footer:
	fail_chunk:
		free(*_data);
		*_data = NULL;
		*_size = 0;
	return 0;
}

void http_stream_writeError(http_stream_t* self,
                            int err, const char* reason)
{
	assert(self);
	assert(reason);

	/*
	 * HTTP/1.1 <status> <string>
	 */
	char header[256];
	snprintf(header, 256,
	         "HTTP/1.1 %i %s\n\n",
	         err, reason);
	header[255] = '\0';

	int len = strlen(header) + 1;

	net_socket_sendall(self->sock, header, len);
	net_socket_flush(self->sock);
}

int http_stream_writeData(http_stream_t* self,
                          int size, void* data)
{
	assert(self);
	assert(data);

	/*
	 * HTTP/1.1 <status> <string>
	 * CONTENT-LENGTH: <len>
	 * <optional>Transfer-Encoding: chunked
	 */
	char header[256];
	snprintf(header, 256,
	         "HTTP/1.1 %i OK\nCONTENT-LENGTH: %i\n\n",
	         HTTP_OK, size);
	header[255] = '\0';

	int len = strlen(header);
	if(net_socket_sendall(self->sock, header, len) == 0)
	{
		return 0;
	}

	if(net_socket_sendall(self->sock, data, size) == 0)
	{
		return 0;
	}

	return net_socket_flush(self->sock);
}
