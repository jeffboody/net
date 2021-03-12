About
=====

This net submodule is intended to simplify the network socket API.

Send questions or comments to Jeff Boody - jeffboody@gmail.com

Optional SSL Setup
==================

Install SSL library:

	sudo apt-get install libssl-dev

Create SSL keys:

	cd sslkeys
	./make-sslkeys.sh

Test SSL keys (run each command in a separate terminal):

	./test-server.sh
	./test-client.sh

SSL References
==============

	Network Security with OpenSSL (O'Reilly)
	https://github.com/zapstar/two-way-ssl-c
	https://gist.github.com/zapstar/4b51d7cfa74c7e709fcdaace19233443
	https://people.freebsd.org/~syrinx/presentations/openssl/OpenSSL-Programming-20140424-01.pdf
	http://h30266.www3.hpe.com/odl/i64os/opsys/vmsos84/BA554_90007/ch04s03.html
	https://aticleworld.com/ssl-server-client-using-openssl-in-c/
	https://quuxplusone.github.io/blog/2020/01/26/openssl-part-3/

License
=======

	Copyright (c) 2013 Jeff Boody

	Permission is hereby granted, free of charge, to any person obtaining a
	copy of this software and associated documentation files (the "Software"),
	to deal in the Software without restriction, including without limitation
	the rights to use, copy, modify, merge, publish, distribute, sublicense,
	and/or sell copies of the Software, and to permit persons to whom the
	Software is furnished to do so, subject to the following conditions:

	The above copyright notice and this permission notice shall be included
	in all copies or substantial portions of the Software.

	THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
	IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
	FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
	AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
	LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
	OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
	THE SOFTWARE.
