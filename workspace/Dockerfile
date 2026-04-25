FROM python:3.12-slim

# Install bws CLI
RUN apt-get update && apt-get install -y curl && rm -rf /var/lib/apt/lists/*
RUN curl -fsSL https://github.com/bitwarden/sdk-sm/releases/download/bws-v2.0.0/bws-x86_64-unknown-linux-gnu-2.0.0.zip \
    -o /tmp/bws.zip && \
    apt-get update && apt-get install -y unzip && \
    unzip /tmp/bws.zip -d /usr/local/bin && \
    chmod +x /usr/local/bin/bws && \
    rm /tmp/bws.zip

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

RUN chmod +x /app/entrypoint.sh

EXPOSE 8000 8001 8002

ENTRYPOINT ["/app/entrypoint.sh"]
