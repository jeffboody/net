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
#include <unistd.h>

#define LOG_TAG "net"
#include "../libcc/cc_log.h"
#include "../libcc/cc_memory.h"
#include "net_httpd.h"

#define NET_HTTPD_RETRY_DELAY 1000000

/***********************************************************
* private                                                  *
***********************************************************/

static int net_httpd_started(net_httpd_t* self)
{
	pthread_mutex_lock(&self->http_mutex);
	while(self->start == 0)
	{
		pthread_cond_wait(&self->http_cond,
		                  &self->http_mutex);
	}
	pthread_mutex_unlock(&self->http_mutex);

	// check for initialization errors
	if(self->start == -1)
	{
		return 0;
	}

	return 1;
}

static void* net_httpd_http(void* arg)
{
	ASSERT(arg);

	net_httpd_t* self = (net_httpd_t*) arg;

	pthread_mutex_lock(&self->http_mutex);
	int tid = self->tid++;
	pthread_mutex_unlock(&self->http_mutex);

	if(net_httpd_started(self) == 0)
	{
		return NULL;
	}

	// accept endlessly
	while(1)
	{
		// wait for a client
		pthread_mutex_lock(&self->http_mutex);
		cc_listIter_t* iter = cc_list_head(self->http_socks);
		while(iter == NULL)
		{
			pthread_cond_wait(&self->http_cond,
			                  &self->http_mutex);
			iter = cc_list_head(self->http_socks);
		}

		net_socket_t* a;
		a = (net_socket_t*)
		    cc_list_remove(self->http_socks, &iter);
		pthread_mutex_unlock(&self->http_mutex);

		LOGD("[HTTP] start a=%p", a);

		// override the default timeout for ANR
		net_socket_timeout(a, 4, 4);

		// serve files
		int count_ok = 0;
		int close    = 0;
		while((close == 0) && (count_ok < 256))
		{
			LOGD("[HTTP] wserve a=%p", a);
			if(net_socket_wserve(a, tid, 0,
			                     self->request_priv,
			                     self->request_fn,
			                     &close) == 0)
			{
				if((net_socket_error(a) == 1) ||
				   (net_socket_connected(a) == 0))
				{
					close = 1;
				}
			}
			else
			{
				++count_ok;
			}

			LOGD("[HTTP] count_ok=%i, close=%i",
			     count_ok, close);
		}

		LOGD("[HTTP] close a=%p", a);
		net_socket_close(&a);
	}

	return NULL;
}

static void* net_httpd_httpd(void* arg)
{
	ASSERT(arg);

	net_httpd_t* self = (net_httpd_t*) arg;

	if(net_httpd_started(self) == 0)
	{
		return NULL;
	}

	// listen endlessly
	net_socket_t* s = NULL;
	while(1)
	{
		// create the listening socket
		if(s == NULL)
		{
			LOGD("[HTTPD] listen");
			s = net_socket_listen(&self->info);
			if(s == NULL)
			{
				// try again
				usleep(NET_HTTPD_RETRY_DELAY);
				continue;
			}
		}

		// wait for a connection
		LOGD("[HTTPD] accept s=%p", s);
		net_socket_t* a = net_socket_accept(s);
		if(a)
		{
			LOGD("[HTTPD] accepting s=%p, a=%p", s, a);

			// pass the request to the handler
			pthread_mutex_lock(&self->http_mutex);
			if(cc_list_append(self->http_socks, NULL, (void*) a))
			{
				pthread_cond_broadcast(&self->http_cond);
			}
			else
			{
				LOGD("[HTTPD] close s=%p", s);
				net_socket_close(&a);
			}
			LOGD("[HTTPD] accepted s=%p, count=%i",
			     s, cc_list_size(self->http_socks));
			pthread_mutex_unlock(&self->http_mutex);
		}

		// close the socket if a problem occurred
		if((a == NULL)                    ||
		   (net_socket_connected(s) == 0) ||
		   (net_socket_error(s)     == 1))
		{
			LOGD("[HTTPD] close s=%p", s);
			net_socket_close(&s);
			usleep(NET_HTTPD_RETRY_DELAY);
		}
	}

	return NULL;
}

/***********************************************************
* public                                                   *
***********************************************************/

net_httpd_t*
net_httpd_new(int nth, net_listenInfo_t* info,
              void* request_priv,
              net_socket_requestFn request_fn)
{
	ASSERT(nth > 0);
	ASSERT(info);
	ASSERT(request_fn);

	net_httpd_t* self;
	self = (net_httpd_t*)
	       CALLOC(1, sizeof(net_httpd_t));
	if(self == NULL)
	{
		LOGE("CALLOC failed");
		return NULL;
	}

	self->nth          = nth;
	self->request_priv = request_priv;
	self->request_fn   = request_fn;

	size_t size = strlen(info->port) + 1;
	char*  port = (char*) MALLOC(size);
	if(port == NULL)
	{
		LOGE("MALLOC failed");
		goto fail_port;
	}
	snprintf(port, size, "%s", info->port);

	char* ca_cert = NULL;
	if(info->ca_cert)
	{
		size    = strlen(info->ca_cert) + 1;
		ca_cert = (char*) MALLOC(size);
		if(ca_cert == NULL)
		{
			LOGE("MALLOC failed");
			goto fail_ca_cert;
		}
		snprintf(ca_cert, size, "%s", info->ca_cert);
	}

	char* server_cert = NULL;
	if(info->server_cert)
	{
		size        = strlen(info->server_cert) + 1;
		server_cert = (char*) MALLOC(size);
		if(server_cert == NULL)
		{
			LOGE("MALLOC failed");
			goto fail_server_cert;
		}
		snprintf(server_cert, size, "%s", info->server_cert);
	}

	char* server_key = NULL;
	if(info->server_key)
	{
		size       = strlen(info->server_key) + 1;
		server_key = (char*) MALLOC(size);
		if(server_key == NULL)
		{
			LOGE("MALLOC failed");
			goto fail_server_key;
		}
		snprintf(server_key, size, "%s", info->server_key);
	}

	self->info.port        = port;
	self->info.ca_cert     = ca_cert;
	self->info.server_cert = server_cert;
	self->info.server_key  = server_key;
	self->info.type        = info->type;
	self->info.flags       = info->flags;

	self->http_socks = cc_list_new();
	if(self->http_socks == NULL)
	{
		goto fail_http_socks;
	}

	if(pthread_mutex_init(&self->http_mutex, NULL) != 0)
	{
		LOGE("pthread_mutex_init failed");
		goto fail_http_mutex;
	}

	if(pthread_cond_init(&self->http_cond, NULL) != 0)
	{
		LOGE("pthread_cond_init failed");
		goto fail_http_cond;
	}

	self->http_thread = (pthread_t*)
	                    CALLOC(nth, sizeof(pthread_t));
	if(self->http_thread == NULL)
	{
		goto fail_http_alloc;
	}

	int t;
	for(t = 0; t < nth; ++t)
	{
		if(pthread_create(&(self->http_thread[t]), NULL,
		                  net_httpd_http, (void*) self) != 0)
		{
			LOGE("pthread_create failed");
			goto fail_http_create;
		}
	}

	if(pthread_create(&self->httpd_thread, NULL,
	                  net_httpd_httpd, (void*) self) != 0)
	{
		LOGE("pthread_create failed");
		goto fail_httpd_create;
	}

	// success
	return self;

	// failure
	fail_httpd_create:
	fail_http_create:
	{
		pthread_mutex_lock(&self->http_mutex);
		self->start = -1;
		pthread_cond_broadcast(&self->http_cond);
		pthread_mutex_unlock(&self->http_mutex);

		int i;
		for(i = 0; i < t; ++i)
		{
			pthread_join(self->http_thread[i], NULL);
		}
		FREE(self->http_thread);
	}
	fail_http_alloc:
		pthread_cond_destroy(&self->http_cond);
	fail_http_cond:
		pthread_mutex_destroy(&self->http_mutex);
	fail_http_mutex:
		cc_list_delete(&self->http_socks);
	fail_http_socks:
		FREE(server_key);
	fail_server_key:
		FREE(server_cert);
	fail_server_cert:
		FREE(ca_cert);
	fail_ca_cert:
		FREE(port);
	fail_port:
		FREE(self);
	return NULL;
}

void net_httpd_delete(net_httpd_t** _self)
{
	ASSERT(_self);

	net_httpd_t* self = *_self;
	if(self)
	{
		ASSERT(self->start == 0);

		pthread_mutex_lock(&self->http_mutex);
		self->start = -1;
		pthread_cond_broadcast(&self->http_cond);
		pthread_mutex_unlock(&self->http_mutex);

		pthread_join(self->httpd_thread, NULL);

		int i;
		for(i = 0; i < self->nth; ++i)
		{
			pthread_join(self->http_thread[i], NULL);
		}

		FREE(self->http_thread);
		pthread_cond_destroy(&self->http_cond);
		pthread_mutex_destroy(&self->http_mutex);
		cc_list_delete(&self->http_socks);
		FREE((void*) self->info.server_key);
		FREE((void*) self->info.server_cert);
		FREE((void*) self->info.ca_cert);
		FREE((void*) self->info.port);
		FREE(self);
		*_self = NULL;
	}
}

void net_httpd_start(net_httpd_t* self, int blocking)
{
	ASSERT(self);

	pthread_mutex_lock(&self->http_mutex);
	self->start = 1;
	pthread_cond_broadcast(&self->http_cond);
	pthread_mutex_unlock(&self->http_mutex);

	if(blocking)
	{
		// threads never exit once started
		// so this function never returns
		pthread_join(self->httpd_thread, NULL);
	}
}
