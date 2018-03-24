from grpc_reflection.v1alpha import reflection
from concurrent import futures
import grpc

from auth import auth_pb2
from auth import auth_pb2_grpc


class AuthenticationService(auth_pb2_grpc.AuthenticationServiceServicer):

    def RequestCredential(self, request, context):
        print('AuthenticationService.RequestCredential called with', request)
        yield auth_pb2.NewCredentialResponse(required_action=(
            auth_pb2.UserAction(url='/')))


def serve():
    server = grpc.server(futures.ThreadPoolExecutor(max_workers=10))
    auth_pb2_grpc.add_AuthenticationServiceServicer_to_server(
            AuthenticationService(), server)
    reflection.enable_server_reflection(('AuthenticationService', ), server)
    server.add_insecure_port('[::]:1214')
    print('GRPC available on port 1214')
    server.start()
    # If the grpc.server is GC'd it will be stopped, so we need to hold
    # on to a reference of it
    return server
