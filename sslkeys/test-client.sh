#!/bin/bash

openssl s_client -CAfile ca/ca_cert.pem -cert client/client_cert.pem -key client/private/client_key.pem
