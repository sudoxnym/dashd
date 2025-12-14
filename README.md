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
docker compose up -d
```

dashboard available at `http://localhost:8085`

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

run without docker:

```bash
pip install -r requirements.txt
python backend.py &
# serve dashboard.html on port 8085
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
