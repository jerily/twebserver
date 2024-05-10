# Create a client certificate

To create a client certificate using the CA key and
certificate you previously generated,
you must go through a multi-step process.
This involves generating a private key for the client,
creating a certificate signing request (CSR),
and then using your CA to sign this CSR to produce a client certificate.
Here’s how to do each step using OpenSSL:

## Step 1: Generate the Client’s Private Key

First, create a private key for the client:
```bash
openssl genrsa -out client.key 2048
```

This command generates a 2048-bit RSA
private key and stores it in the file client.key.

## Step 2: Generate the Client’s Certificate Signing Request (CSR)

With the private key, you can now generate a CSR.
The CSR includes identifying information such as
the organization and common name (CN),
which should be the client’s name or identifier.

```bash
openssl req -new -key client.key -out client.csr
```

This command creates a new CSR (client.csr)
using the private key (client.key).
You will be prompted to enter the client's information
such as country, state, locality, organization name,
organizational unit, common name (client's name), and email address.
Ensure that the common name or CN is unique to the client.

## Step 3: Create a Certificate for the Client Signed by your CA

Now, use the CA key and certificate to sign the client’s CSR
and create the client certificate:

```bash
openssl x509 -req -in client.csr -CA ../ca/ca.crt -CAkey ../ca/ca.key -CAcreateserial -out client.crt -days 365 -sha256
```

## Step 4: Test client verification using curl

To test client verification, you can use curl.
```bash
curl -v -k --cert client.crt --key client.key  https://www.example.com:4433/blog/12345/sayhi
```