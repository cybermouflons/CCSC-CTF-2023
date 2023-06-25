FROM php:7.4-apache

COPY app /var/www/html/

RUN sed -i "s/Listen 80/Listen 8080/" /etc/apache2/ports.conf 
RUN chown -R www-data:www-data /var/www/html/