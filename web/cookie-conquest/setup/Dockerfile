# Use the base image with PHP 7.4
FROM php:7.4-apache

# Enable Apache mod_rewrite
RUN a2enmod rewrite

# Copy the application files to the container
COPY ./app /var/www/html

# Set the working directory
WORKDIR /var/www/html
