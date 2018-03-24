from grpc_reflection.v1alpha import reflection
from concurrent import futures
import grpc

from auth import auth_pb2
from auth import auth_pb2_grpc
from auth import internal_pb2


class AuthenticationService(auth_pb2_grpc.AuthenticationServiceServicer):

    def __init__(self, web_challenge):
        self.web_challenge = web_challenge

    def RequestUserCredential(self, request, context):
        print('AuthenticationService.RequestUserCredential: ', request)
        # RequestUserCredentials will always require an identity challenge
        # to protect against someone giving a user their challenge by
        # for example IM-ing the URL to somebody else.
        challenge, event = self.web_challenge.new_challenge()
        yield auth_pb2.CredentialResponse(required_action=challenge)
        if event.wait(timeout=60.0) == False:
            return
        yield auth_pb2.CredentialResponse()


def serve(web_challenge):
    server = grpc.server(futures.ThreadPoolExecutor(max_workers=10))
    auth_pb2_grpc.add_AuthenticationServiceServicer_to_server(
            AuthenticationService(web_challenge), server)
    reflection.enable_server_reflection(('AuthenticationService', ), server)
    server.add_insecure_port('[::]:1214')
    print('GRPC available on port 1214')
    server.start()
    # If the grpc.server is GC'd it will be stopped, so we need to hold
    # on to a reference of it
    return server
