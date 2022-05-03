FROM python:3.8-slim

RUN mkdir -p /analyzer

ADD ./requirements.txt /analyzer
RUN apt-get update \
    && apt-get install -y --no-install-recommends gcc \
    && rm -rf /var/lib/apt/lists/* \
    && pip install --no-cache-dir -r /analyzer/requirements.txt \
    && apt-get purge -y --auto-remove gcc

COPY ./data /analyzer/data
ADD ./crl_check.py /analyzer
ADD ./db.py /analyzer
ADD ./ssl_analyzer.py /analyzer
ADD ./analyzer.conf /analyzer
ADD ./conf_reader.py /analyzer

WORKDIR /analyzer

ENTRYPOINT ["python", "ssl_analyzer.py"]