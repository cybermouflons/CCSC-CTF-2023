#!/bin/bash
IMAGE_NAME=ccsc2023/ciphered-protocol-assault-build
SOURCE_PATH=/workspace/traces.h5
DESTINATION_PATH=traces.h5

docker build . -t $IMAGE_NAME


CONTAINER_ID=$(docker create "$IMAGE_NAME")
docker cp "$CONTAINER_ID:$SOURCE_PATH" "$DESTINATION_PATH"
docker rm "$CONTAINER_ID"
docker rmi $IMAGE_NAME