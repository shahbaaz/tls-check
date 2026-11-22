#!/bin/sh
# Makes the CA-signed test certificates: a test CA and a leaf for test.example signed by it.
# Valid for 100 years; tests pass their own "now" to check expiry. Run from this directory.
# (test-cert.pem is a separate self-signed certificate for test.example.)
set -eu

openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -days 36500 \
  -subj "/CN=TLS Check Test CA" -keyout ca-key.pem -out ca-cert.pem

openssl req -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes \
  -subj "/CN=test.example" -keyout leaf-key.pem -out leaf.csr

openssl x509 -req -in leaf.csr -CA ca-cert.pem -CAkey ca-key.pem -days 36500 \
  -extfile /dev/stdin -out leaf-cert.pem <<'EOF'
subjectAltName = DNS:test.example, DNS:*.wild.example
basicConstraints = CA:FALSE
EOF

# The CA key isn't needed by the tests; rerun this script to make new certificates.
rm leaf.csr ca-key.pem
