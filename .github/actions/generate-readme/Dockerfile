FROM python:3.8-slim-buster

# Copies your code file from your action repository to the filesystem path `/` of the container
COPY entrypoint.py /entrypoint.py
COPY README.jinja /README.jinja
# Python dependencies
RUN pip install pyyaml jinja2

# File to execute when the docker container starts up (`entrypoint.sh`)
ENTRYPOINT ["python", "/entrypoint.py"]