FROM php:8.2-cli

WORKDIR /app

# Install system dependencies and PHP extensions
RUN apt-get update && apt-get install -y \
    git \
    unzip \
    && docker-php-ext-install bcmath

COPY composer.json composer.lock ./
COPY src/App.php ./src/
COPY deploy_tool/composer.json deploy_tool/composer.lock ./deploy_tool/

RUN php -r "copy('https://getcomposer.org/installer','composer-setup.php');" \
    && php composer-setup.php --install-dir=/usr/local/bin --filename=composer \
    && rm composer-setup.php \
    && composer install --no-dev --optimize-autoloader \
    && cd deploy_tool && composer install --no-dev --optimize-autoloader

COPY . .

WORKDIR /app

EXPOSE 8080

CMD ["sh", "-c", "php -S 0.0.0.0:${PORT:-8080} router.php"]
