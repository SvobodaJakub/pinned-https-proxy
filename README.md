# pinned-https-proxy
A primitive HTTPS proxy with certificate pinning for use with servers that use a self-signed certificate

## Use

1. Download the server's self-signed certificate

```
python3 save_cert.py -f mycert.pem -d 192.168.1.44 -p 8089
```

2. Manually check the SHA256 fingerprint of the certificate to prevent MITM. The point of the proxy is that this is the only time you have to verify the certificate.

3. Run the proxy with the force-pinned certificate. The proxy enforces that the connection is encrypted with this certificate and uses secure (as of 10/2017) ciphersuites.

```
python3 proxy.py -f mycert.pem -a 192.168.1.44 -p 8089 -l 8080
```

4. Point your web browser to the exact same URL as you would with the original server, except for the address, port, and protocol. E.g.:

```
http://127.0.0.1:8080/woolnote?otp=abcdefgh
```

## Bugs

* Doesn't work with non-self-signed certificates.
* Doesn't rewrite the address in the links in the proxied HTML.
* Extraneous headers.


