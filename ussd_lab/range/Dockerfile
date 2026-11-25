FROM python:3.12-slim
RUN apt-get update && apt-get install -y --no-install-recommends openssl && rm -rf /var/lib/apt/lists/* && pip install --no-cache-dir flask requests
WORKDIR /app
COPY . /app
CMD ["sh", "/app/start.sh"]
