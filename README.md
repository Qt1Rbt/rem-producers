# HIK_ALARM_FORWARD

This project contains a C program (`main.c`).

> [!CAUTION]
> Don't meant to be use / copied for prod usage. This is a simple program that watch for thermal alarm in HIK event stream and send them to a redis queue. This is possibly/probably not memory safe, will leak passwords if passed as args and redis is probably not the best choice for important message handling.

## Dependencies

This project requires the following libraries:
- `libcurl`
- `libxml2`
- `pthread` (usually included in standard C library)

### Install dependencies (Ubuntu/Debian):

```
sudo apt-get update
sudo apt-get install -y build-essential libcurl4-openssl-dev libxml2-dev
#cd /usr/include && sudo ln -s libxml2/libxml .
```

## Compilation

To compile the project locally:

```
gcc -o hik_alarm_forward main.c -lcurl -lxml2 -lpthread -I/usr/include/libxml2
```

## Docker Build

A GitHub Actions workflow is provided to build the project in a Docker container and export the resulting binary as a `.tar` artifact.

## Requirements
- Docker
- (Optional) GitHub Actions for CI builds

## Usage

After building, run the binary:

```
./hik_alarm_forward
```
# rem-producers
