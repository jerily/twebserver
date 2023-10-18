# Generate certs

To use the library, you will need to generate a key and certificate.  You can do this with the following commands:
```bash
# First go into the directory where the certificate should be stored.
openssl genrsa -out key.pem
openssl req -new -key key.pem -out csr.pem
openssl x509 -req -days 9999 -in csr.pem -signkey key.pem -out cert.pem
```

Alternatively, you can use the following command:
```bash
# First go into the directory where the certificate should be stored.
openssl req -x509 \
        -newkey rsa:4096 \
        -keyout key.pem \
        -out cert.pem \
        -sha256 \
        -days 3650 \
        -nodes \
        -subj "/C=CY/ST=Cyprus/L=Home/O=none/OU=CompanySectionName/CN=localhost/CN=www.example.com"
```
