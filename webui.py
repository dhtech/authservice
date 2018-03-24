import http.server
import socket
import socketserver
import threading

from auth import auth_pb2
from auth import auth_pb2_grpc


class Tcp6Server(socketserver.TCPServer):
    address_family = socket.AF_INET6


class HttpRequestHandler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200)
        self.send_header('Content-type', 'text/html')
        self.end_headers()

        self.wfile.write(bytes('<html><body><h1>Hello</h1></body></html>', 'utf-8'))
        return


def serve():
    httpd = Tcp6Server(('::', 80), HttpRequestHandler)
    server_thread = threading.Thread(target=httpd.serve_forever)
    print('Web frontend available on port 80')
    server_thread.daemon = True
    server_thread.start()
    return httpd
