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

#ifndef net_httpd_H
#define net_httpd_H

#include <pthread.h>

#include "../libcc/cc_list.h"
#include "net_socket.h"

typedef struct
{
	int                  start;
	int                  tid;
	int                  nth;
	net_listenInfo_t     info;
	void*                request_priv;
	net_socket_requestFn request_fn;
	cc_list_t*           http_socks;
	pthread_mutex_t      http_mutex;
	pthread_cond_t       http_cond;
	pthread_t*           http_thread;
	pthread_t            httpd_thread;
} net_httpd_t;

net_httpd_t* net_httpd_new(int nth,
                           net_listenInfo_t* info,
                           void* request_priv,
                           net_socket_requestFn request_fn);
void         net_httpd_delete(net_httpd_t** _self);
void         net_httpd_start(net_httpd_t* self);

#endif
