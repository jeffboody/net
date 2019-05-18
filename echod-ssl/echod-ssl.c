/*
 * Copyright (c) 2019 Jeff Boody
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

#include "net/net_socketSSL.h"
#include <stdio.h>
#include <stdlib.h>

int main(int argc, const char** argv)
{
	if(argc != 2)
	{
		printf("%s port\n", argv[0]);
		return EXIT_FAILURE;
	}

	net_socketSSL_t* s;
	s = net_socketSSL_listen(argv[1], NET_SOCKETSSL_TCP, 1);
	if(s == NULL)
	{
		return EXIT_FAILURE;
	}

	net_socketSSL_t* a = net_socketSSL_accept(s);
	if(a == NULL)
	{
		goto fail_accept;
	}

	char buf[256];
	while(1)
	{
		int recvd;
		net_socketSSL_recv(a, buf, 255, &recvd);
		if(net_socketSSL_error(a))
		{
			// failed to recv
			goto fail_echo;
		}
		else if(net_socketSSL_connected(a) == 0)
		{
			// normal shutdown
			break;
		}
		else
		{
			buf[recvd] = '\0';
			printf("%s", buf);
		}

		net_socketSSL_sendall(a, buf, recvd);
		if(net_socketSSL_error(a))
		{
			// failed to send
			goto fail_echo;
		}
	}

	net_socketSSL_close(&a);
	net_socketSSL_close(&s);

	// success
	return EXIT_SUCCESS;

	// failure
	fail_echo:
		net_socketSSL_close(&a);
	fail_accept:
		net_socketSSL_close(&s);
	return EXIT_FAILURE;
}
