FROM php:7.4-apache

RUN apt-get update && docker-php-ext-install mysqli pdo pdo_mysql

COPY src /var/www/html/

COPY flag.txt /flag.txt 

RUN chown -R www-data:www-data /var/www/html/
