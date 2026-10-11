# Linux peer for avahi_test.go: avahi-daemon with its command-line tools,
# plus the avahipeer binary (github.com/cB-Sigma/mdns), which the test
# builds for Linux and puts next to this file.
FROM alpine:3.20.3
RUN apk add --no-cache avahi avahi-tools dbus
COPY avahipeer /usr/local/bin/avahipeer
COPY start.sh /start.sh
RUN chmod 0755 /start.sh /usr/local/bin/avahipeer
ENTRYPOINT ["/start.sh"]
