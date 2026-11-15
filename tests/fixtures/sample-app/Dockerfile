FROM python:latest
RUN apt-get update && apt-get install -y curl
WORKDIR /app
COPY . .
RUN pip install -r requirements.txt
EXPOSE 8080
CMD python server.py
