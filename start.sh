#!/bin/bash
# start all services

python3 /app/backend.py &
python3 /app/mail_proxy.py &
python3 /app/browser_proxy.py &
nginx -g 'daemon off;'
