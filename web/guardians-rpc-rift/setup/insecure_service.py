import grpc
import urllib.request
import time
from concurrent import futures

from flag_pb2 import ExternalDataRequest, ExternalDataResponse
from flag_pb2_grpc import ExternalDataServiceServicer, add_ExternalDataServiceServicer_to_server

class ExternalDataServicer(ExternalDataServiceServicer):
    def GetData(self, request, context):
        file_path = request.url
        with open(file_path, 'r') as file:
            data = file.read()
        return ExternalDataResponse(data=data)

# Create a gRPC server and add the service
server = grpc.server(futures.ThreadPoolExecutor())
add_ExternalDataServiceServicer_to_server(ExternalDataServicer(), server)

# Start the server
server.add_insecure_port('[::]:50051')
server.start()

# Wait for the server to stop
try:
    while True:
        time.sleep(86400)
except KeyboardInterrupt:
    server.stop(0)
