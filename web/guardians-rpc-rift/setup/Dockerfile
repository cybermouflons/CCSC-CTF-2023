# Use a base image with the necessary dependencies
FROM python:3.9-slim

# Set the working directory inside the container
WORKDIR /app

# Copy the necessary files into the container
COPY requirements.txt .
COPY *.py .
COPY insecure_service.py .
COPY flag_pb2.py .
COPY flag_pb2_grpc.py .
COPY static_html /app/static_html
COPY flag.proto /app/static_html/flag.proto
COPY flag.txt /app/flag.txt

# Install dependencies
RUN pip install --no-cache-dir -r requirements.txt
RUN pip install --no-cache-dir protobuf

# Install Nginx
RUN apt-get update && apt-get install -y nginx

COPY nginx.conf /etc/nginx/nginx.conf

# Expose the gRPC service port and the web server port
EXPOSE 50051 80

# Run the gRPC service and start Nginx
CMD service nginx start && python insecure_service.py
