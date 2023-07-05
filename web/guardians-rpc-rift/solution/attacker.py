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
