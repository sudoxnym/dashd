FROM python:3.11-slim

ENV DEBIAN_FRONTEND=noninteractive

WORKDIR /app

# install nginx first
RUN apt-get update &&     apt-get install -y --no-install-recommends nginx &&     rm -rf /var/lib/apt/lists/*

# install python deps
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# copy app files
COPY backend.py .
COPY mail_proxy.py .
COPY browser_proxy.py .
COPY nginx.conf /etc/nginx/nginx.conf
COPY dashboard.html ./static/

# create data dir
RUN mkdir -p /data

# start script
COPY start.sh .
RUN chmod +x start.sh

EXPOSE 8085

CMD ["./start.sh"]
COPY dashd_icon.png ./static/
