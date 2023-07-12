FROM python:3.10-slim-buster

WORKDIR /chall

COPY . .

RUN pip install poetry

RUN poetry install && poetry run python -m app.initdb

RUN rm app/initdb.py

ENTRYPOINT poetry run uvicorn --host 0.0.0.0 app.main:app