FROM python:3.9-slim

WORKDIR /app

COPY . .

RUN pip install --no-cache-dir flask flask-login

CMD ["python", "-m", "flask", "run", "--host=0.0.0.0"]