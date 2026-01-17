#!/bin/bash

# Kill existing PHP processes to avoid conflicts (optional, be careful if other php things are running)
pkill -f "php -S 0.0.0.0:8000"
pkill -f "php license_bot.php"

echo "Starting License Bot..."
php license_bot.php > bot.log 2>&1 &
BOT_PID=$!
echo "License Bot started with PID $BOT_PID"

echo "Starting Web Server..."
php -S 0.0.0.0:8000 index.php > server.log 2>&1 &
SERVER_PID=$!
echo "Web Server started with PID $SERVER_PID"

echo "Services are running. Logs: bot.log, server.log"
