FROM mcr.microsoft.com/playwright:v1.35.0-jammy

RUN apt update -y && \
    apt install -y python3-pip

WORKDIR /chall

COPY . .

RUN pip install poetry

RUN poetry install && \
    poetry run playwright install chromium && \
    poetry run playwright install-deps

ENTRYPOINT poetry run uvicorn --host 0.0.0.0 --port 8080 app:app