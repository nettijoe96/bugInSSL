openssl x509 -req -in csr.pem -CA cacert.pem -CAkey cakey.pem -CAcreateserial -out $1
