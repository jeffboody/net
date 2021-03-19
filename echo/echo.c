/*
 * Copyright (c) 2017 Jeff Boody
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

/*
 * send a message to the server and log received message
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define LOG_TAG "echo"
#include "libcc/cc_log.h"
#include "net/net_socket.h"

int main(int argc, const char** argv)
{
	if(argc != 4)
	{
		printf("%s addr port message\n", argv[0]);
		return EXIT_FAILURE;
	}

	net_connectInfo_t info =
	{
		.addr  = argv[1],
		.port  = argv[2],
		.type  = NET_SOCKET_TYPE_TCP,
		.flags = 0
	};

	// connect to addr
	net_socket_t* sock;
	sock = net_socket_connect(&info);
	if(sock == NULL)
	{
		LOGE("net_socket_connect failed");
		return EXIT_FAILURE;
	}

	net_socket_timeout(sock, 4, 4);

	const char* msg = argv[3];
	int len = strlen(msg) + 1;
	if(net_socket_sendall(sock, msg, len) == 0)
	{
		goto fail_send;
	}

	char buf[256];
	int recvd = 0;
	if(net_socket_recv(sock, buf, 256, &recvd) == 0)
	{
		goto fail_recv;
	}
	buf[255] = '\0';

	LOGI("send=%s", msg);
	LOGI("recv=%s", buf);

	net_socket_close(&sock);

	// success
	return EXIT_SUCCESS;

	// failure
	fail_recv:
	fail_send:
		net_socket_close(&sock);
	return EXIT_FAILURE;
}
