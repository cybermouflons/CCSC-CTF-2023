FROM python:3.9

WORKDIR /app

COPY flag.txt /flag-25bc0a2d93af28813.txt

COPY requirements.txt .

RUN pip install -r requirements.txt

COPY middleware/ middleware
COPY pyjwt/ pyjwt
COPY routes/ routes
COPY app.py app.py
COPY database.py database.py
COPY models.py models.py
COPY utils.py utils.py

RUN pip install -e pyjwt

EXPOSE 3000

CMD ["python", "app.py"]
