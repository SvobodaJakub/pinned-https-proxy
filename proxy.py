# A simple proxy intended to be used with Woolnote.
# Serves https pages with one pinned self-signed certificate.
# Fails with most other servers.

import ssl
import urllib.request
from OpenSSL.crypto import load_certificate, FILETYPE_PEM
import argparse
from http.server import BaseHTTPRequestHandler
from http.server import HTTPServer
import os

parser = argparse.ArgumentParser()
parser.add_argument("-f", "--file", help="File name with the pinned cert", required=True)
parser.add_argument("-a", "--address", help="Server address where to connect to.", required=True)
parser.add_argument("-p", "--port", help="Server port where to connect to.")
parser.add_argument("-l", "--local-port", help="Local port where to serve the proxy to the client.")
parser.add_argument("--no-cert-check", help="Do not check cert. Dangerous. Vulnerable to MITM.",
                    action="store_true")
parser.add_argument("--no-set-secure-ciphersuites",
                    help="Do not set secure ciphersuites. Dangerous. Vulnerable to MITM.",
                    action="store_true")
args = parser.parse_args()

port = 443
if args.port:
    port = args.port

local_port = 8080
if args.local_port:
    local_port = args.local_port

with open(args.file, 'r') as certfile:
    mycert = certfile.read()


def get_fingerprint_sha256_str_from_cert(cert_pem_str):
    cert = load_certificate(FILETYPE_PEM, cert_pem_str)
    # proper certificate fingerprint, the same as displayed by a web browser
    sha256_fingerprint = cert.digest("sha256").decode("utf8")
    return sha256_fingerprint


sha256_fingerprint = get_fingerprint_sha256_str_from_cert(mycert)
print("Fingerprint of the trusted pinned certificate: {}".format(sha256_fingerprint))


def create_ssl_context():
    # ssl context with one pinned certificate and secure cipher suites
    # the connection will fail if not secured with this cert or ciphersuite
    # hostname not checked so that private IP address can be used
    # the certificate can be self-signed and it doesn't matter because it is implicitly trusted and pinned
    myssl = ssl.create_default_context(purpose=ssl.Purpose.SERVER_AUTH, cadata=mycert);
    myssl.check_hostname = False
    myssl.verify_mode = ssl.CERT_REQUIRED
    if args.no_cert_check:
        myssl.verify_mode = ssl.CERT_NONE
    if not args.no_set_secure_ciphersuites:
        myssl.set_ciphers(
            "ECDHE-RSA-AES256-GCM-SHA384:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-RSA-AES256-SHA384")
    return myssl


def fetch_get(full_url_with_proto_and_port, ssl_context, headers=None):
    code = 200
    api = full_url_with_proto_and_port
    if not headers:
        headers = {}
    request = urllib.request.Request(api, headers=headers, method="GET")
    try:
        response = urllib.request.urlopen(request, context=ssl_context)
    except urllib.error.HTTPError as e:
        code = e.code
        response = e  # https://docs.python.org/3.1/howto/urllib2.html#error-codes
    # on purpose not doing except urllib.error.URLError as e:
    response_str = response.read()
    headers_str = str(response.info())
    headers = headers_str.strip().split("\n")
    return response_str, headers, code


def fetch_post(full_url_with_proto_and_port, ssl_context, data, headers=None):
    code = 200
    api = full_url_with_proto_and_port
    if not headers:
        headers = {}
    request = urllib.request.Request(api, headers=headers, data=data, method="POST")
    try:
        response = urllib.request.urlopen(request, context=ssl_context)
    except urllib.error.HTTPError as e:
        code = e.code
        response = e  # https://docs.python.org/3.1/howto/urllib2.html#error-codes
    # on purpose not doing except urllib.error.URLError as e:
    response_str = response.read()
    headers_str = str(response.info())
    headers = headers_str.strip().split("\n")
    return response_str, headers, code


def fetch_head(full_url_with_proto_and_port, ssl_context, headers=None):
    code = 200
    api = full_url_with_proto_and_port
    if not headers:
        headers = {}
    request = urllib.request.Request(api, headers=headers, method="HEAD")
    try:
        response = urllib.request.urlopen(request, context=ssl_context)
    except urllib.error.HTTPError as e:
        code = e.code
        response = e  # https://docs.python.org/3.1/howto/urllib2.html#error-codes
    # on purpose not doing except urllib.error.URLError as e:
    headers_str = str(response.info())
    headers = headers_str.strip().split("\n")
    return headers, code


def get_WebInterfaceHandlerLocal(destination_addr, destination_port):
    """
    Returns the class for the web request handler which has access to data in the arguments. (Because the class is
    then used in such a way that it's not possible to pass additional arguments to its __init__().)
    Args:
        destination_addr (str): Address of the server that is queried through the proxy
        destination_port (int): Port of the server that is queried through the proxy

    Returns:
        type: class WebInterfaceHandlerLocal(BaseHTTPRequestHandler) that holds the arguments in its scope
    """

    class WebInterfaceHandlerLocal(BaseHTTPRequestHandler):

        def do_GET(self):
            # gather client's request
            host = str(destination_addr)
            port = str(destination_port)
            path = str(self.path)
            headers = self.headers

            # resend the client's request to the server
            # gather server's response
            api = 'https://{}:{}{}'.format(host, port, path)
            myssl = create_ssl_context()
            response, headers, code = fetch_get(api, myssl, headers=headers)

            # send server's response to the client
            self.send_response(code)
            for header in headers:
                print(repr(header))
                k, v = header.split(":", 1)
                self.send_header(k.strip(), v.strip())
            self.end_headers()
            try:
                self.wfile.write(response)
            except ssl.SSLEOFError:
                # TODO - why is suppress_ragged_eofs ignored?
                print("ssl.SSLEOFError (#TODO in the code)")

        def do_POST(self):
            # gather client's request
            host = str(destination_addr)
            port = str(destination_port)
            path = str(self.path)
            headers = self.headers
            data = self.rfile.read(int(self.headers['Content-Length']))

            # resend the client's request to the server
            # gather server's response
            api = 'https://{}:{}{}'.format(host, port, path)
            myssl = create_ssl_context()
            response, headers, code = fetch_post(api, myssl, data, headers=headers)

            # send server's response to the client
            self.send_response(code)
            for header in headers:
                print(repr(header))
                k, v = header.split(":", 1)
                self.send_header(k.strip(), v.strip())
            self.end_headers()
            try:
                self.wfile.write(response)
            except ssl.SSLEOFError:
                # TODO - why is suppress_ragged_eofs ignored?
                print("ssl.SSLEOFError (#TODO in the code)")

        def do_HEAD(self):
            # gather client's request
            host = str(destination_addr)
            port = str(destination_port)
            path = str(self.path)
            headers = self.headers

            # resend the client's request to the server
            # gather server's response
            api = 'https://{}:{}{}'.format(host, port, path)
            myssl = create_ssl_context()
            headers, code = fetch_head(api, myssl, headers=headers)

            # send server's response to the client
            self.send_response(code)
            for header in headers:
                print(repr(header))
                k, v = header.split(":", 1)
                self.send_header(k.strip(), v.strip())
            self.end_headers()

    return WebInterfaceHandlerLocal


def serve_proxy_forever(local_port, remote_addr, remote_port):
    """
    Starts the http request handler that serves the proxy and blocks forever.
    """

    WebInterfaceHandlerLocal = get_WebInterfaceHandlerLocal(remote_addr, remote_port)

    def get_server_on_port(port, use_ssl=False):
        server = HTTPServer(("", port), WebInterfaceHandlerLocal)
        if use_ssl:
            # TODO this is just copy&paste from Woolnote and is non-functional in its current form; it's just there for the future in case someone wants this proxy expose it as https
            try:
                print("use_ssl=True, trying")
                ssl_cert_path = os.path.join(config.PATH_DIR_FOR_SSL_CERT_PEM, config.FILE_CERT_PEM)
                ssl_key_path = os.path.join(config.PATH_DIR_FOR_SSL_KEY_PEM, config.FILE_KEY_PEM)
                server.socket = ssl.wrap_socket(server.socket, certfile=ssl_cert_path,
                                                keyfile=ssl_key_path, server_side=True,
                                                suppress_ragged_eofs=True)
                # TODO: for some reason, suppress_ragged_eofs is ignored
            except:
                print("use_ssl=True, FAILED!")
        else:
            print("use_ssl=False")
        print("returning server")
        return server

    def serve_on_port(port, use_ssl=False):
        server = get_server_on_port(port, use_ssl)
        print("trying serve_forever")
        server.serve_forever()

    server_http = get_server_on_port(local_port, False)

    def serve_forever(*servers):
        # https://stackoverflow.com/questions/60680/how-do-i-write-a-python-http-server-to-listen-on-multiple-ports
        import select
        while True:
            r, w, e = select.select(servers, [], [], 10)
            for server in servers:
                if server in r:
                    server.handle_request()

    serve_forever(server_http)


serve_proxy_forever(int(local_port), args.address, port)
