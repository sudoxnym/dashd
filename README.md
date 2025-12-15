# dashd

cyberpunk infrastructure dashboard with user authentication and docker deployment.

![dashd](https://raw.githubusercontent.com/sudoxnym/dashd/master/dashd_icon.png)

## features

- grid-locked card positioning with drag/resize
- youtube widgets (click-to-play to avoid csp errors)
- service health monitoring
- user authentication with server-side storage
- per-user localstorage caching
- docker deployment ready

## quick start

```bash
# pull and run
docker run -d -p 8085:8085 -v dashd_data:/data sudoxreboot/dashd

# or with compose
curl -O https://raw.githubusercontent.com/sudoxnym/dashd/master/docker-compose.yml
docker compose up -d
```

dashboard available at `http://localhost:8085`

## docker compose

```yaml
services:
  dashd:
    image: sudoxreboot/dashd:latest
    ports:
      - "8085:8085"
    volumes:
      - dashd_data:/data
    environment:
      - DASHD_SECRET=${DASHD_SECRET:-}
    restart: unless-stopped

volumes:
  dashd_data:
```

## configuration

set a custom jwt secret:

```bash
DASHD_SECRET=your-secret-here docker compose up -d
```

or in `.env`:

```
DASHD_SECRET=your-secret-here
```

## development

build from source:

```bash
git clone https://github.com/sudoxnym/dashd.git
cd dashd
docker build -t dashd .
docker run -d -p 8085:8085 dashd
```

## architecture

- `dashboard.html` - single-page dashboard
- `backend.py` - fastapi auth + settings api (sqlite)
- `mail_proxy.py` - email checking proxy
- `browser_proxy.py` - cors proxy for external services
- `nginx.conf` - reverse proxy config
- `Dockerfile` + `docker-compose.yml` - containerized deployment

## license

mit

---

<div align="center">

made by [sudoxnym](https://sudoxreboot.com) ⚡

</div>
