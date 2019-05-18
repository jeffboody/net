#!/bin/bash

openssl s_server -CAfile ca/ca_cert.pem -cert server/server_cert.pem -key server/private/server_key.pem -Verify 1
