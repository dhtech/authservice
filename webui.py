import http.cookies
import http.server
import pamela
import socket
import socketserver
import threading
import urllib
import uuid

from auth import auth_pb2
from auth import auth_pb2_grpc
from auth import internal_pb2


class Tcp6Server(socketserver.TCPServer):
    address_family = socket.AF_INET6


class HttpRequestHandler(http.server.BaseHTTPRequestHandler):

    def _require_challenge(self):
        path = urllib.parse.urlparse(self.path)
        challenge = str(urllib.parse.parse_qs(path.query)['challenge'][0])
        if not self.server.challenge.has(challenge):
            self.send_response(404)
            self.end_headers()
            self.wfile.write(b'No such challenge')
            return None
        return challenge

    def _cookie(self, user):
        c = http.cookies.Morsel()
        c.key = 'tech-auth'
        c.value = user
        c['secure'] = 1;
        c['domain'] = '*.tech.dreamhack.se'
        # TODO: actual cookie here, not just the user of course :-)
        return c.OutputString()

    def do_GET(self):
        path = urllib.parse.urlparse(self.path)
        if path.path == '/auth':
            if self._require_challenge() is None:
                return
            self.send_response(200)
            self.send_header('content-type', 'text/html')
            self.end_headers()
            with open('login.html', 'rb') as f:
                self.wfile.write(f.read())
            return

        self.send_response(200)
        self.end_headers()
        self.wfile.write(b'404')
        return

    def do_POST(self):
        """Handle client login challenges.

        The authentication system challenged the user to prove their identity,
        that's why we are here. This could be because the cookie has
        expired, or the thing we're authenticating cannot trust only a cookie.

        If the user succeeds in logging in, mark the challenge as completed
        and mint a new credentials cookie.
        """
        path = urllib.parse.urlparse(self.path)
        if path.path != '/auth':
            self.send_response(405)
            self.end_headers()
            self.wfile.write(b'Method not allowed')
            return

        challenge = self._require_challenge()
        if challenge is None:
            return
        length = int(self.headers['content-length'])
        body = urllib.parse.parse_qs(self.rfile.read(length))
        user = None
        try:
            user = body[b'username'][0]
            pamela.authenticate(user, body[b'password'][0], 'login')
            # Remove sensitive credentials to prevent accidental dumps
            body = {}
        except pamela.PAMError:
            self.send_response(401)
            self.end_headers()
            self.wfile.write(b'Login failed')
            return
        # Success! Poke the challenge and return a new authentication cookie
        ip, port, _, _ = self.client_address
        self.server.challenge.finish(
                challenge, internal_pb2.WebChallengeResponse(
                    challenge=challenge, user=user, ip=ip, port=port))
        self.send_response(200)
        self.send_header('set-cookie', self._cookie(user))
        self.send_header('content-type', 'text/html')
        self.end_headers()
        self.wfile.write(b'Login OK')


class WebChallenge(object):

    def __init__(self):
        self.challenges = {}

    def new(self):
        challenge = str(uuid.uuid1())
        event = threading.Event()
        self.challenges[challenge] = [event, None]
        action = auth_pb2.UserAction(url='/auth?challenge=' + challenge)
        return challenge, action, event

    def has(self, challenge):
        return challenge in self.challenges

    def finish(self, challenge, result):
        self.challenges[challenge][1] = result
        self.challenges[challenge][0].set()

    def ack(self, challenge):
        response = self.challenges[challenge][1]
        del self.challenges[challenge]
        return response


def serve():
    httpd = Tcp6Server(('::', 80), HttpRequestHandler)
    httpd.challenge = WebChallenge()
    server_thread = threading.Thread(target=httpd.serve_forever)
    print('Web frontend available on port 80')
    server_thread.daemon = True
    server_thread.start()
    return httpd
