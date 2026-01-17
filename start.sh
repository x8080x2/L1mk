#!/bin/bash

# Use PORT environment variable if available (Render), otherwise default to 8000 (Local)
PORT="${PORT:-8000}"

# Kill existing PHP processes to avoid conflicts (suppress errors if none found)
# Useful for local dev, usually harmless on Render
pkill -f "php -S 0.0.0.0" > /dev/null 2>&1 || true
pkill -f "php license_bot.php" > /dev/null 2>&1 || true

echo "Running License Migration..."
php migrate_license.php

echo "Starting License Bot..."
php license_bot.php > bot.log 2>&1 &
BOT_PID=$!
echo "License Bot started with PID $BOT_PID"

echo "Starting Web Server on port $PORT..."

# Check if running on Render or in Docker (foreground mode required)
if [ ! -z "$RENDER" ] || [ -f /.dockerenv ]; then
    echo "Running in container mode (foreground)..."
    # Execute the web server in the foreground, filtering out noisy connection logs
    # Using --line-buffered to ensure real-time logging for other messages
    php -S 0.0.0.0:$PORT index.php 2>&1 | grep --line-buffered -vE "Accepted|Closing|Closed without sending a request"
else
    # Local mode (background)
    php -S 0.0.0.0:$PORT index.php > server.log 2>&1 &
    SERVER_PID=$!
    echo "Web Server started with PID $SERVER_PID"
    echo "Services are running. Logs: bot.log, server.log"
fi
