FROM gcc:latest
WORKDIR /app
# Install required libraries
RUN apt-get update && \
	apt-get install -y libcurl4-openssl-dev libxml2-dev libhiredis-dev && \
	rm -rf /var/lib/apt/lists/*

COPY main.c ./
# Build with required libraries
RUN gcc -o hik_alarm_forward main.c -lcurl -lxml2 -lhiredis -lpthread -I/usr/include/libxml2

CMD ["./hik_alarm_forward"]
