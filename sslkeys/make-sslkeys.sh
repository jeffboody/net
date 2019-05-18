#!/bin/bash

# ca_cert.pem
mkdir -p ca/private
chmod 700 ca/private
openssl req \
    -x509 \
    -nodes \
    -days 3650 \
    -newkey rsa:4096 \
    -keyout ca/private/ca_key.pem \
    -out ca/ca_cert.pem \
    -subj "/C=US/ST=Colorado/L=Boulder/CN=jeffboody.com/emailAddress=jeffboody@gmail.com"

# server_key.pem
mkdir -p server/private
chmod 700 server/private
openssl genrsa -out server/private/server_key.pem 4096
openssl req -new \
    -key server/private/server_key.pem \
    -out server/server.csr \
    -subj "/C=US/ST=Colorado/L=Boulder/CN=server.jeffboody.com/emailAddress=jeffboody@gmail.com"

# client_key.pem
mkdir -p client/private
chmod 700 client/private
openssl genrsa -out client/private/client_key.pem 4096
openssl req -new \
    -key client/private/client_key.pem \
    -out client/client.csr \
    -subj "/C=US/ST=Colorado/L=Boulder/CN=client.jeffboody.com/emailAddress=jeffboody@gmail.com"

# server_cert.pem
openssl x509 -req -days 3650 -in server/server.csr \
    -CA ca/ca_cert.pem -CAkey ca/private/ca_key.pem \
    -CAcreateserial -out server/server_cert.pem

# client_cert.pem
openssl x509 -req -days 3650 -in client/client.csr \
    -CA ca/ca_cert.pem -CAkey ca/private/ca_key.pem \
    -CAcreateserial -out client/client_cert.pem
