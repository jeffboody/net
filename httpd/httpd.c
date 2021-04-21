/*
 * Copyright (c) 2021 Jeff Boody
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

#define LOG_TAG "httpd"
#include "libcc/cc_log.h"
#include "net/net_httpd.h"
#include "net/net_socket.h"

int main(int argc, const char** argv)
{
	int ssl = 0;
	const char* port;
	if(argc == 2)
	{
		port = argv[1];
	}
	else if((argc == 3) &&
	        (strcmp(argv[1], "-ssl") == 0))
	{
		ssl  = 1;
		port = argv[2];
	}
	else
	{
		LOGE("%s [-ssl] port", argv[0]);
		return EXIT_FAILURE;
	}

	int ssl_flags = NET_SOCKET_FLAG_SSL |
	                NET_SOCKET_FLAG_SSL_LISTEN_ANYONE;
	net_listenInfo_t info =
	{
		.port        = port,
		.ca_cert     = ssl ? "ca_cert.pem"     : NULL,
		.server_cert = ssl ? "server_cert.pem" : NULL,
		.server_key  = ssl ? "server_key.pem"  : NULL,
		.type        = NET_SOCKET_TYPE_TCP,
		.flags       = ssl ? ssl_flags : 0
	};

	net_httpd_t* httpd;
	httpd = net_httpd_new(1, &info, NULL,
	                      net_socket_requestFile);
	if(httpd == NULL)
	{
		return EXIT_FAILURE;
	}
	net_httpd_start(httpd);
}
