---
title: Reverse proxy and HTTPS
description: Reach VulWall from other machines through a TLS reverse proxy, with Caddy or nginx examples.
---

VulWall serves plain HTTP on port 8080, and Docker Compose publishes it on `127.0.0.1` only. To
use it from other machines, put a reverse proxy in front of it that terminates TLS.

:::caution[Do not publish port 8080 on all interfaces]
Changing the port mapping to `"8080:8080"` is not a safe shortcut. Docker writes its own iptables
rules, so ports it publishes bypass host firewalls such as ufw and firewalld, and anyone who can
reach the host gets plain HTTP.
:::

## Steps

1. Run the proxy and point it at VulWall:
   - proxy on the host: `http://127.0.0.1:8080` (or your `VULWALL_PORT`);
   - proxy in a Docker container: add the container to the `vulwall_default` network and point it
     at `http://web:8080`.
2. Set `SECURE_COOKIES=true` in `.env`. This turns on Secure cookies, HSTS and the redirect from
   HTTP to HTTPS.
3. Set `TRUSTED_PROXIES` in `.env` to the proxy's address as VulWall sees it (see below).
4. Apply the settings: `docker compose up -d`.

## TRUSTED_PROXIES

VulWall reads the client's IP address and the original scheme from the `X-Forwarded-For` and
`X-Forwarded-Proto` headers, but only for requests that come from an address in
`TRUSTED_PROXIES`. The value is a comma-separated list of IP addresses or CIDR ranges.

- **Proxy on the host:** connections reach the web container from the gateway of the
  `vulwall_default` network. Find it with:

  ```sh
  docker network inspect vulwall_default --format '{{(index .IPAM.Config 0).Gateway}}'
  ```

- **Proxy in a container:** use that container's address on `vulwall_default`:

  ```sh
  docker inspect <proxy-container> --format '{{(index .NetworkSettings.Networks "vulwall_default").IPAddress}}'
  ```

This setting matters for rate limiting. Login attempts are rate-limited per client IP (5 failed
attempts per 15 minutes). If `TRUSTED_PROXIES` does not match your proxy, VulWall sees every
request as coming from the proxy, so all users share one limit and a few wrong passwords lock
everyone out. Login also has a limit for the admin account of 20 attempts per 15 minutes from all
addresses together.

## Caddy

Caddy gets a certificate from Let's Encrypt and sets the forwarded headers by default.
`/etc/caddy/Caddyfile`:

```caddy
vulwall.example.com {
	reverse_proxy 127.0.0.1:8080
}
```

## nginx

```nginx
server {
    listen 80;
    server_name vulwall.example.com;
    return 301 https://$host$request_uri;
}

server {
    listen 443 ssl;
    http2 on;
    server_name vulwall.example.com;

    ssl_certificate     /etc/letsencrypt/live/vulwall.example.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/vulwall.example.com/privkey.pem;

    location / {
        proxy_pass http://127.0.0.1:8080;
        proxy_set_header Host $host;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
}
```

## Example .env

```sh
SECURE_COOKIES=true
TRUSTED_PROXIES=172.18.0.1
```

Replace `172.18.0.1` with the address you found above.
