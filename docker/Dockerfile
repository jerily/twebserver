FROM alpine:latest
ENV TZ=UTC
RUN ln -snf /usr/share/zoneinfo/$TZ /etc/localtime && echo $TZ > /etc/timezone
RUN apk add \
    linux-headers \
    bsd-compat-headers \
    bash \
    perl \
    gcc \
    g++ \
    binutils-gold \
    cmake \
    make \
    patch \
    pkgconfig \
    cvs \
    git \
    curl \
    zip \
    unzip \
    gdb

RUN mkdir -p /var/www/sample-project
COPY install.sh /var/www/sample-project/install.sh
COPY start.sh /var/www/sample-project/start.sh

ENV LD_LIBRARY_PATH="/var/www/sample-project/local/lib:/var/www/sample-project/local/lib64"

RUN chmod +x /var/www/sample-project/start.sh
RUN chmod +x /var/www/sample-project/install.sh && /var/www/sample-project/install.sh

COPY examples /var/www/sample-project/examples

EXPOSE 8080
EXPOSE 4443
STOPSIGNAL SIGTERM

ENTRYPOINT ["/var/www/sample-project/start.sh"]