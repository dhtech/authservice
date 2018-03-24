auth_pb2.py:
	python3 -m grpc_tools.protoc -I../protos --python_out=. --grpc_python_out=. ../protos/auth/auth.proto
