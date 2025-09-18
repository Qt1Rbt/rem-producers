# --- Build Stage ---
FROM gcc:trixie AS builder
WORKDIR /app

RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        libcurl4-openssl-dev libxml2-dev libhiredis-dev && \
    rm -rf /var/lib/apt/lists/*

COPY main.c ./
RUN gcc -o hik_alarm_forward main.c -lcurl -lxml2 -lhiredis -lpthread -I/usr/include/libxml2 && \
    strip hik_alarm_forward

# --- Runtime Stage ---
FROM debian:trixie-slim
WORKDIR /app

RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        libcurl4 libxml2 libhiredis1.1.0 && \
    rm -rf /var/lib/apt/lists/*

COPY --from=builder /app/hik_alarm_forward ./

CMD ["./hik_alarm_forward"]