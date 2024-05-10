# Testing client verification

## Step 1: Generate a Private Key for the CA

First, you need to generate a private key.
You can do this with the following command.
For a stronger key, you might choose 4096 bits.
```bash
openssl genrsa -out ca.key 2048
```

## Step 2: Generate a Self-Signed Certificate for the CA

Using the private key you just created,
you can now generate a self-signed certificate.
This certificate serves as the CA certificate.
You will use it to sign other certificates.

```bash
openssl req -x509 -new -nodes -key ca.key -sha256 -days 1024 -out ca.crt
```

## Step 3: Verify the CA Certificate

You can verify the CA certificate with the following command.
```bash
openssl x509 -in ca.crt -text -noout
```