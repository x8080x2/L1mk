FROM php:8.2-cli

WORKDIR /app

# Install system dependencies and PHP extensions
RUN apt-get update && apt-get install -y \
    git \
    unzip \
    libzip-dev \
    && docker-php-ext-configure zip \
    && docker-php-ext-install bcmath zip

COPY composer.json composer.lock ./

RUN php -r "copy('https://getcomposer.org/installer','composer-setup.php');" \
    && php composer-setup.php --install-dir=/usr/local/bin --filename=composer \
    && rm composer-setup.php \
    && composer install --no-dev --optimize-autoloader

COPY . .

RUN chmod +x start.sh

WORKDIR /app

EXPOSE 8080

CMD ["./start.sh"]
