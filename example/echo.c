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

/*
 * echo runs as a server and returns any messages it receives
 */

#include "net/net_socket.h"
#include <stdio.h>
#include <stdlib.h>

int main(int argc, char** argv)
{
	if(argc < 2)
	{
		printf("%s port\n", argv[0]);
		return EXIT_FAILURE;
	}

	net_socket_t* s = net_socket_listen(argv[1], NET_SOCKET_TCP, 1);
	if(s == NULL)
	{
		return EXIT_FAILURE;
	}

	net_socket_t* a = net_socket_accept(s);
	if(a == NULL)
	{
		goto fail_accept;
	}

	int cnt_recv;
	int cnt_send;
	char buf[256];
	while(1)
	{
		cnt_recv = net_socket_recv(a, buf, 255);
		if(cnt_recv > 0)
		{
			buf[cnt_recv] = '\0';
			printf("%s", buf);
		}
		else
		{
			// failed to recv
			goto fail_echo;
		}

		cnt_send = net_socket_send(a, buf, cnt_recv);
		if(cnt_send != cnt_recv)
		{
			// failed to send
			goto fail_echo;
		}
	}

	net_socket_close(&a);
	net_socket_close(&s);

	// success
	return EXIT_SUCCESS;

	// failure
	fail_echo:
		net_socket_close(&a);
	fail_accept:
		net_socket_close(&s);
	return EXIT_FAILURE;
}
