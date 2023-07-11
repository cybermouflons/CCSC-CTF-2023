FROM openresty/openresty:1.19.9.1-1-buster-fat

# Copy nginx configuration
COPY nginx.conf /usr/local/openresty/nginx/conf/nginx.conf
COPY api_keys.lua /etc/nginx/api_keys.lua

EXPOSE 9000

CMD ["/usr/local/openresty/bin/openresty", "-g", "daemon off;"]