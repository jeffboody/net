/*
 * Copyright (c) 2016 Jeff Boody
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

#include "net/net_socket.h"
#include "net/net_socket_wget.h"
#include <stdio.h>
#include <stdlib.h>

int main(int argc, const char** argv)
{
	if(argc != 2)
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

	int close = 0;
	if(net_socket_wserve(a, 0, NULL, NULL, &close) == 0)
	{
		goto fail_serve;
	}

	net_socket_close(&a);
	net_socket_close(&s);

	// success
	return EXIT_SUCCESS;

	// failure
	fail_serve:
		net_socket_close(&a);
	fail_accept:
		net_socket_close(&s);
	return EXIT_FAILURE;
}
