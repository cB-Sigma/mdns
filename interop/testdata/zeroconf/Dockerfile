# Linux peer for zeroconf_test.go: python-zeroconf (LGPL-2.1) with the
# driver zcpeer.py, plus the avahipeer binary (github.com/cB-Sigma/mdns),
# which the test builds for Linux and puts next to this file.
FROM python:3.12.10-slim
RUN pip install --no-cache-dir zeroconf==0.151.5
COPY avahipeer /usr/local/bin/avahipeer
COPY zcpeer.py /usr/local/bin/zcpeer.py
ENTRYPOINT ["sleep", "2147483647"]
