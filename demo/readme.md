## Keys ansd Certificate Notice:

All key files and certificate files are created as sample files for public access.
They are published intentionally for OpenSSL code practice.

### File creation:

cacert.key: ```openssl genrsa -out ./demo/cacert.key 2048```

cacert.pem: ```openssl req -x509 -new -nodes -key ./demo/cacert.key -sha256 -days 7320 -out ./demo/cacert.pem```

cert-file.key: ```openssl genrsa -out ./demo/cert-file.key 2048```

cert-csr.pem: ```openssl req -new -addext "subjectAltName = DNS:alt.fm4dd.com" -addext "basicConstraints = critical,CA:FALSE" -addext "keyUsage = digitalSignature,keyEncipherment,dataEncipherment" -key ./demo/cert-file.key -out ./demo/cert-csr.pem```

cert-file.pem: ```openssl x509 -req -copy_extensions=copyall -days 3650 -in ./demo/cert-csr.pem -CA ./demo/cacert.pem -CAkey ./demo/cacert.key -out ./demo/cert-file.pem```

cabundle.pem: ```wget https://curl.haxx.se/ca/cacert.pem -O demo/cabundle.pem```

webcert-crl.pem: ```wget http://webcert.fm4dd.com/webcert.crl -O demo/webcert.crl```

webcert-crl.der ```openssl crl -in demo/webcert.crl -outform DER -out demo/webcert-crl.der```
