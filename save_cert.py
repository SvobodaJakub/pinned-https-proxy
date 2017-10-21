# A simple https certificate downloader intended to be used with Woolnote.

import argparse
import ssl
import urllib.request
from OpenSSL.crypto import load_certificate, FILETYPE_PEM

parser = argparse.ArgumentParser()
parser.add_argument("-f", "--file", help="File name where to save the cert", required=True)
parser.add_argument("-d", "--host", help="Host where to retrieve the cert from.", required=True)
parser.add_argument("-p", "--port", help="Port of the host where to retrieve the cert from.")
args = parser.parse_args()

if not args.port:
    port = 443
else:
    port = args.port

cert = ssl.get_server_certificate((args.host, port))
print("Certificate:")
print(cert)

with open(args.file, "w") as text_file:
    text_file.write(cert)


def get_fingerprint_sha256_str_from_cert(cert_pem_str):
    cert = load_certificate(FILETYPE_PEM, cert_pem_str)
    # proper certificate fingerprint, the same as displayed by a web browser
    sha256_fingerprint = cert.digest("sha256").decode("utf8")
    return sha256_fingerprint


sha256_fingerprint = get_fingerprint_sha256_str_from_cert(cert)
print("Fingerprint of the certificate: {}".format(sha256_fingerprint))
