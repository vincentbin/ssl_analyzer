FROM python:3.8-slim

ADD ./requirements.txt /
RUN apt-get update \
    && apt-get install -y --no-install-recommends gcc \
    && rm -rf /var/lib/apt/lists/* \
    && pip install --no-cache-dir -r /requirements.txt \
    && apt-get purge -y --auto-remove gcc

COPY ./data /data
ADD ./crl_check.py /
ADD ./db.py /
ADD ./ssl_analyzer.py /
ADD ./test.py /

ENTRYPOINT ["python", "/ssl_analyzer.py"]
