#!/bin/bash

# ca_cert.pem
# The CN of the root CA is your name.
mkdir -p ca/private
chmod 700 ca/private
openssl req \
    -x509 \
    -nodes \
    -days 3650 \
    -newkey rsa:4096 \
    -keyout ca/private/ca_key.pem \
    -out ca/ca_cert.pem \
    -subj "/C=US/ST=Colorado/L=Boulder/CN=Jeff Boody/emailAddress=jeffboody@gmail.com"

# server_key.pem
# The server CN must be a fully qualified domain name.
mkdir -p server/private
chmod 700 server/private
openssl genrsa -out server/private/server_key.pem 4096
openssl req -new \
    -key server/private/server_key.pem \
    -out server/server.csr \
    -subj "/C=US/ST=Colorado/L=Boulder/CN=localhost/emailAddress=jeffboody@gmail.com"

# client_key.pem
# The client CN may be any unique identifier.
mkdir -p client/private
chmod 700 client/private
openssl genrsa -out client/private/client_key.pem 4096
openssl req -new \
    -key client/private/client_key.pem \
    -out client/client.csr \
    -subj "/C=US/ST=Colorado/L=Boulder/CN=Net Client App/emailAddress=jeffboody@gmail.com"

# server_cert.pem
openssl x509 -req -days 3650 -in server/server.csr \
    -CA ca/ca_cert.pem -CAkey ca/private/ca_key.pem \
    -CAcreateserial -out server/server_cert.pem

# client_cert.pem
openssl x509 -req -days 3650 -in client/client.csr \
    -CA ca/ca_cert.pem -CAkey ca/private/ca_key.pem \
    -CAcreateserial -out client/client_cert.pem
