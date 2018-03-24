auth_pb2.py:
	python3 -m grpc_tools.protoc -I../proto --python_out=. --grpc_python_out=. ../proto/auth/auth.proto
