#!/bin/sh
# Makes the CA-signed test certificates. Valid for 100 years; tests pass their own "now"
# to check expiry. Run from this directory.
#
#   ca-cert.pem                  test root ("TLS Check Test CA")
#   leaf-cert.pem, leaf-key.pem  test.example and *.wild.example, signed by the root directly
#   intermediate-cert.pem        an intermediate CA, signed by the root
#   chain-leaf-cert.pem, -key    test.example, signed by the intermediate
#   signed-by-leaf-cert.pem      signed with leaf-key.pem: its issuer isn't a CA
#   no-san-cert.pem, -key        subject O=TLS Check Test (no CN), SAN with an IP address only
#   no-subject-cert.pem, -key    empty subject, SAN test.example
#   crl-leaf-cert.pem, -key      test.example with a CRL URL, signed by the root, not revoked
#   revoked-leaf-cert.pem, -key  the same, but listed as revoked in root.crl
#   root.crl                     the root's CRL (DER), listing revoked-leaf-cert.pem
#
# (test-cert.pem is a separate self-signed certificate for test.example.)
set -eu

openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -days 36500 \
  -subj "/CN=TLS Check Test CA" -keyout ca-key.pem -out ca-cert.pem

# sign <csr> <issuer cert> <issuer key> <out> <extensions>
sign() {
  echo "$5" | openssl x509 -req -in "$1" -CA "$2" -CAkey "$3" -days 36500 -extfile /dev/stdin -out "$4"
}

openssl req -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes \
  -subj "/CN=test.example" -keyout leaf-key.pem -out leaf.csr
sign leaf.csr ca-cert.pem ca-key.pem leaf-cert.pem \
  "subjectAltName = DNS:test.example, DNS:*.wild.example
basicConstraints = CA:FALSE"

openssl req -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes \
  -subj "/CN=TLS Check Test Intermediate" -keyout intermediate-key.pem -out intermediate.csr
sign intermediate.csr ca-cert.pem ca-key.pem intermediate-cert.pem \
  "basicConstraints = critical, CA:TRUE
keyUsage = critical, keyCertSign, cRLSign"

openssl req -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes \
  -subj "/CN=test.example" -keyout chain-leaf-key.pem -out chain-leaf.csr
sign chain-leaf.csr intermediate-cert.pem intermediate-key.pem chain-leaf-cert.pem \
  "subjectAltName = DNS:test.example
basicConstraints = CA:FALSE"

openssl req -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes \
  -subj "/CN=other.example" -keyout signed-by-leaf-key.pem -out signed-by-leaf.csr
sign signed-by-leaf.csr leaf-cert.pem leaf-key.pem signed-by-leaf-cert.pem \
  "subjectAltName = DNS:other.example
basicConstraints = CA:FALSE"

openssl req -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes \
  -subj "/O=TLS Check Test" -keyout no-san-key.pem -out no-san.csr
sign no-san.csr ca-cert.pem ca-key.pem no-san-cert.pem \
  "subjectAltName = IP:192.0.2.1
basicConstraints = CA:FALSE"

openssl req -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes \
  -subj "/" -keyout no-subject-key.pem -out no-subject.csr
sign no-subject.csr ca-cert.pem ca-key.pem no-subject-cert.pem \
  "subjectAltName = critical, DNS:test.example
basicConstraints = CA:FALSE"

for name in crl-leaf revoked-leaf; do
  openssl req -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes \
    -subj "/CN=test.example" -keyout $name-key.pem -out $name.csr
  sign $name.csr ca-cert.pem ca-key.pem $name-cert.pem \
    "subjectAltName = DNS:test.example
basicConstraints = CA:FALSE
crlDistributionPoints = URI:http://crl.test.example/root.crl"
done

# A CRL from the root listing revoked-leaf-cert.pem, made with a throwaway "openssl ca" setup.
cat > ca.cnf <<'CNF'
[ca]
default_ca = test
[test]
database = index.txt
crlnumber = crlnumber
default_md = sha256
default_crl_days = 36500
CNF
: > index.txt
echo 01 > crlnumber
openssl ca -config ca.cnf -keyfile ca-key.pem -cert ca-cert.pem -revoke revoked-leaf-cert.pem -crl_reason keyCompromise
openssl ca -config ca.cnf -keyfile ca-key.pem -cert ca-cert.pem -gencrl -out root-crl.pem
openssl crl -in root-crl.pem -outform DER -out root.crl

# The CA keys aren't needed by the tests; rerun this script to make new certificates.
rm ./*.csr ca.cnf index.txt* crlnumber* root-crl.pem ca-key.pem intermediate-key.pem signed-by-leaf-key.pem
