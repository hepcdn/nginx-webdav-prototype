# Heavily based on https://github.com/openresty/docker-openresty/blob/master/centos/Dockerfile
FROM docker.io/almalinux:9 as build

ARG RESTY_VERSION="1.27.1.1"
ARG RESTY_LUAROCKS_VERSION="3.11.1"
# TODO: arch specific build

WORKDIR /usr/local/src

RUN yum groupinstall -y "Development Tools" \
    && yum install -y pcre-devel openssl-devel

COPY set-default-verify-dir.patch .

RUN curl -Ol https://openresty.org/download/openresty-${RESTY_VERSION}.tar.gz \
    && tar -xzf openresty-${RESTY_VERSION}.tar.gz \
    && cd openresty-${RESTY_VERSION} \
    && patch bundle/nginx-1.27.1/src/event/ngx_event_openssl.c ../set-default-verify-dir.patch \
    && ./configure --prefix=/usr/local/openresty --with-pcre-jit -j2 \
    && make -j2 \
    && make install \
    && cd .. \
    && curl -fSL https://luarocks.github.io/luarocks/releases/luarocks-${RESTY_LUAROCKS_VERSION}.tar.gz -o luarocks-${RESTY_LUAROCKS_VERSION}.tar.gz \
    && tar xzf luarocks-${RESTY_LUAROCKS_VERSION}.tar.gz \
    && cd luarocks-${RESTY_LUAROCKS_VERSION} \
    && ./configure \
        --prefix=/usr/local/openresty/luajit \
        --with-lua=/usr/local/openresty/luajit \
        --with-lua-include=/usr/local/openresty/luajit/include/luajit-2.1 \
    && make build \
    && make install

RUN /usr/local/openresty/luajit/bin/luarocks install luaposix

RUN /usr/local/openresty/luajit/bin/luarocks install lua-resty-openidc

RUN /usr/local/openresty/luajit/bin/luarocks install lua-zlib

FROM docker.io/almalinux:9

RUN yum install -y pcre openssl zlib dnsmasq epel-release libuv \
    && dnf config-manager --set-enabled crb \ 
    && yum install -y libuv-devel \
    && yum clean all

COPY --from=build /usr/local/openresty /usr/local/openresty

ENV PATH=$PATH:/usr/local/openresty/luajit/bin:/usr/local/openresty/nginx/sbin:/usr/local/openresty/bin

# Add LuaRocks paths
# If OpenResty changes, these may need updating:
#    /usr/local/openresty/bin/resty -e 'print(package.path)'
#    /usr/local/openresty/bin/resty -e 'print(package.cpath)'
ENV LUA_PATH="/usr/local/openresty/site/lualib/?.ljbc;/usr/local/openresty/site/lualib/?/init.ljbc;/usr/local/openresty/lualib/?.ljbc;/usr/local/openresty/lualib/?/init.ljbc;/usr/local/openresty/site/lualib/?.lua;/usr/local/openresty/site/lualib/?/init.lua;/usr/local/openresty/lualib/?.lua;/usr/local/openresty/lualib/?/init.lua;./?.lua;/usr/local/openresty/luajit/share/luajit-2.1/?.lua;/usr/local/share/lua/5.1/?.lua;/usr/local/share/lua/5.1/?/init.lua;/usr/local/openresty/luajit/share/lua/5.1/?.lua;/usr/local/openresty/luajit/share/lua/5.1/?/init.lua"

ENV LUA_CPATH="/usr/local/openresty/site/lualib/?.so;/usr/local/openresty/lualib/?.so;./?.so;/usr/local/lib/lua/5.1/?.so;/usr/local/openresty/luajit/lib/lua/5.1/?.so;/usr/local/lib/lua/5.1/loadall.so;/usr/local/openresty/luajit/lib/lua/5.1/?.so"

RUN mkdir -p /var/run/openresty \
    && ln -sf /dev/stdout /usr/local/openresty/nginx/logs/access.log \
    && ln -sf /dev/stderr /usr/local/openresty/nginx/logs/error.log

# Copy nginx configuration files
COPY nginx.conf /usr/local/openresty/nginx/conf/nginx.conf

COPY conf.d /etc/nginx/conf.d

COPY lua /etc/nginx/lua

COPY docker-entrypoint.sh /
CMD ["nginx", "-g", "daemon off;"]
ENTRYPOINT ["/docker-entrypoint.sh"]
