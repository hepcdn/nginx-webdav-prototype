#!/bin/bash

# Set defaults
SERVER_NAME=${SERVER_NAME:-localhost}
PORT=${PORT:-8080}
USE_SSL=${USE_SSL:-false}
SSL_HOST_CERT=${SSL_HOST_CERT:-/etc/grid-security/hostcert.pem}
SSL_HOST_KEY=${SSL_HOST_KEY:-/etc/grid-security/hostkey.pem}
SSL_CERT_DIR=${SSL_CERT_DIR:-/etc/grid-security/certificates}
DEBUG=${DEBUG:-false}

if [ "$USE_SSL" == "true" ]; then
  cat <<EOF > /etc/nginx/conf.d/site.conf
server {
    listen              $PORT ssl;
    listen              [::]:$PORT ssl;
    server_name         $SERVER_NAME;
    ssl_certificate     $SSL_HOST_CERT;
    ssl_certificate_key $SSL_HOST_KEY;
    ssl_protocols       TLSv1.2 TLSv1.3;
    ssl_ciphers         HIGH:!aNULL:!MD5;

    include /etc/nginx/conf.d/include/locations.conf;
}
EOF
else
  cat <<EOF > /etc/nginx/conf.d/site.conf
server {
    listen              $PORT;
    listen              [::]:$PORT;
    server_name         $SERVER_NAME;

    include /etc/nginx/conf.d/include/locations.conf;
}
EOF
fi

if [ "$DEBUG" == "true" ]; then
  cat <<EOF >> /etc/nginx/conf.d/site.conf
error_log stderr notice;

server {
    lua_code_cache off;

    location /webdav {
        rewrite_log on;
    }
}
EOF
fi

export SSL_CERT_DIR=$SSL_CERT_DIR

# Start a dns server (just for respecting /etc/hosts)
dnsmasq -kd &
# Run target executable (probably nginx)
exec "$@"
