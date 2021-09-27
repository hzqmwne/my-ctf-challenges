FROM python:3.8

RUN pip3 install pycryptodome
COPY --chown=root:root server.py secret.py /

USER 1000:1000
CMD ["/bin/sh", "-c", "python3 -u /server.py 2>/dev/null"]
