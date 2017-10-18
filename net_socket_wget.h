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

#ifndef net_socket_wget_H
#define net_socket_wget_H

#include "net_socket.h"

typedef int (*net_socket_request_fn)(void* priv,
                                     const char* request,
                                     int* _size,
                                     void** _data);

int net_socket_wget(net_socket_t* self,
                    const char* user_agent,
                    const char* request,
                    int close,
                    int* _size, void** _data);
int net_socket_wserve(net_socket_t* self, int chunked,
                      void* request_priv,
                      net_socket_request_fn request_fn,
                      int* close);
int net_socket_requestFile(void* priv,
                           const char* request,
                           int* _size,
                           void** _data);

#endif
