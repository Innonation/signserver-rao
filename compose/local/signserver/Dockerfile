FROM python:3.6

ENV PYTHONUNBUFFERED 1
ENV PYTHONDONTWRITEBYTECODE 1
ENV SECRET_KEY 940da9ef97dfb093563293d7a62d695e205e2fa25cd7a59d

RUN apt-get update \
    && apt-get install -y build-essential \
    # sqlite binaries for maintenance
    && apt-get install -y sqlite3 \
    # Cleaning up unused files.
    && apt-get purge -y --auto-remove -o APT::AutoRemove::RecommendsImportant=false \
    && rm -rf /var/lib/apt/lists/* \
    && mkdir -p /signserver /data \
    && adduser --uid 1001 --no-create-home --gecos root --shell /bin/sh --home /signserver signserver \
    && usermod -a -G root signserver

COPY ./compose/local/signserver/start ./compose/production/signserver/entrypoint /
COPY . /signserver

RUN pip install -r /signserver/requirements.txt \
    && chown -R 1001:0 /signserver /data \
    && chmod -R g+rwXs /data /signserver


USER 1001
EXPOSE 8003
VOLUME /data

WORKDIR /
CMD ["/start"]
ENTRYPOINT ["/entrypoint"]
