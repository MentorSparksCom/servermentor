# Proxy Authentication Examples

Use proxy authentication when ServerMentor should trust identity headers injected by a reverse proxy, access gateway, or auth sidecar instead of running its own OAuth login flow.

## App Configuration

Proxy-only mode:

```env
AUTH_MODE=proxy
AUTH_PROXY_DISPLAY_NAME=Company SSO
AUTH_PROXY_TRUSTED_PROXIES=127.0.0.1/32
AUTH_ADMIN_EMAILS=admin@example.com
AUTH_PROXY_SUBJECT_HEADERS=X-Forwarded-User
AUTH_PROXY_EMAIL_HEADERS=X-Forwarded-Email
AUTH_PROXY_GROUPS_HEADERS=X-Forwarded-Groups
```

In this mode, ServerMentor only accepts identity from trusted proxy headers. Built-in MentorLogin or GitHub login is not used.

Mixed mode, where proxy auth is available alongside built-in providers:

```env
AUTH_PROVIDERS=mentorlogin,github
AUTH_PROXY_ENABLED=true
AUTH_PROXY_TRUSTED_PROXIES=10.0.0.10/32
AUTH_ADMIN_EMAILS=admin@example.com
```

In this mode, trusted proxy headers are accepted first, but the app can still use the providers listed in `AUTH_PROVIDERS` when those headers are not present.

Notes:

- `AUTH_PROXY_TRUSTED_PROXIES` must contain the actual IP or CIDR of the reverse proxy that reaches the app, not the user's browser IP.
- Leave `AUTH_PROXY_TRUST_ALL=false` unless the app is in a tightly controlled internal network.
- The login button for proxy auth goes straight to `/admin`, so users must enter through the protected reverse-proxy hostname or path.

## Header Contract

By default the app accepts these header families:

- Subject: `X-Forwarded-User`, `X-Auth-Request-User`, `Remote-User`
- Email: `X-Forwarded-Email`, `X-Auth-Request-Email`, `Remote-Email`
- Groups: `X-Forwarded-Groups`, `X-Auth-Request-Groups`
- Orgs: `X-Forwarded-Orgs`, `X-Auth-Request-Orgs`
- Teams: `X-Forwarded-Teams`, `X-Auth-Request-Teams`

Multiple groups, orgs, or teams can be sent as a comma-separated header value.

## Example 1: Nginx auth_request

This pattern works well when `oauth2-proxy`, Authentik, or another auth gateway exposes an auth-check endpoint and returns identity headers to Nginx.

```nginx
upstream servermentor {
    server 127.0.0.1:8080;
}

upstream oauth2_proxy {
    server 127.0.0.1:4180;
}

server {
    listen 80;
    server_name servermentor.example.com;

    location = /oauth2/auth {
        proxy_pass http://oauth2_proxy;
        proxy_pass_request_body off;
        proxy_set_header Content-Length "";
        proxy_set_header X-Original-URI $request_uri;
    }

    location /oauth2/ {
        proxy_pass http://oauth2_proxy;
    }

    location / {
        auth_request /oauth2/auth;
        error_page 401 = /oauth2/start?rd=$request_uri;

        auth_request_set $auth_user $upstream_http_x_auth_request_user;
        auth_request_set $auth_email $upstream_http_x_auth_request_email;
        auth_request_set $auth_groups $upstream_http_x_auth_request_groups;

        proxy_set_header X-Forwarded-User $auth_user;
        proxy_set_header X-Forwarded-Email $auth_email;
        proxy_set_header X-Forwarded-Groups $auth_groups;
        proxy_pass http://servermentor;
    }
}
```

Recommended app env for this setup:

```env
AUTH_MODE=proxy
AUTH_PROXY_TRUSTED_PROXIES=127.0.0.1/32
AUTH_PROXY_SUBJECT_HEADERS=X-Forwarded-User
AUTH_PROXY_EMAIL_HEADERS=X-Forwarded-Email
AUTH_PROXY_GROUPS_HEADERS=X-Forwarded-Groups
```

## Example 2: Traefik ForwardAuth

This pattern works when Traefik calls an external auth service and forwards response headers back to ServerMentor.

```yaml
labels:
  - traefik.http.routers.servermentor.rule=Host(`servermentor.example.com`)
  - traefik.http.routers.servermentor.entrypoints=websecure
  - traefik.http.routers.servermentor.middlewares=servermentor-auth
  - traefik.http.middlewares.servermentor-auth.forwardauth.address=http://auth-gateway:9000/auth/traefik
  - traefik.http.middlewares.servermentor-auth.forwardauth.trustForwardHeader=true
  - traefik.http.middlewares.servermentor-auth.forwardauth.authResponseHeaders=X-Forwarded-User,X-Forwarded-Email,X-Forwarded-Groups
```

Recommended app env for this setup:

```env
AUTH_MODE=proxy
AUTH_PROXY_TRUSTED_PROXIES=10.0.0.10/32
AUTH_PROXY_SUBJECT_HEADERS=X-Forwarded-User
AUTH_PROXY_EMAIL_HEADERS=X-Forwarded-Email
AUTH_PROXY_GROUPS_HEADERS=X-Forwarded-Groups
```

Replace `10.0.0.10/32` with the actual Traefik source IP or the specific subnet between Traefik and the app.

## Example 3: oauth2-proxy directly in front of the app

If you want GitHub, Google, or another provider handled entirely by `oauth2-proxy`, you can put it directly in front of ServerMentor and let it pass user headers through.

A runnable Compose example for this layout lives at `examples/docker-compose.oauth2-proxy.yml`. It starts Postgres, runs ServerMentor from the checked-out source tree, and fronts it with `oauth2-proxy` on `http://localhost:4180`.

Start it with:

```bash
docker compose -f examples/docker-compose.oauth2-proxy.yml up
```

Before starting, set these shell variables or put them in an env file that Docker Compose can read:

```env
OAUTH2_PROXY_CLIENT_ID=github-oauth-app-client-id
OAUTH2_PROXY_CLIENT_SECRET=github-oauth-app-client-secret
OAUTH2_PROXY_COOKIE_SECRET=replace-with-32-byte-base64-secret
AUTH_SESSION_SECRET=replace-with-a-long-random-secret
AUTH_ADMIN_EMAILS=admin@example.com
```

```bash
oauth2-proxy \
  --provider=github \
  --http-address=0.0.0.0:4180 \
  --upstream=http://servermentor:8080 \
  --reverse-proxy=true \
  --pass-user-headers=true \
    --scope="read:user user:email read:org" \
  --cookie-secure=true \
  --email-domain=* \
  --client-id=$OAUTH2_PROXY_CLIENT_ID \
  --client-secret=$OAUTH2_PROXY_CLIENT_SECRET \
  --cookie-secret=$OAUTH2_PROXY_COOKIE_SECRET
```

Recommended app env for this setup:

```env
AUTH_MODE=proxy
AUTH_PROXY_TRUSTED_PROXIES=172.20.0.5/32
AUTH_PROXY_SUBJECT_HEADERS=X-Forwarded-User
AUTH_PROXY_EMAIL_HEADERS=X-Forwarded-Email
AUTH_PROXY_NAME_HEADERS=X-Forwarded-Preferred-Username
AUTH_ADMIN_EMAILS=admin@example.com
```

If you authorize with GitHub orgs or teams in the app, make sure your proxy layer actually emits org or team headers and map them with `AUTH_PROXY_ORGS_HEADERS` or `AUTH_PROXY_TEAMS_HEADERS`.

## Choosing Authorization Rules

Use one of these app-side authorization strategies after proxy auth establishes identity:

- `AUTH_ADMIN_EMAILS` for a small static admin list.
- `AUTH_ADMIN_GROUPS` when your proxy forwards group membership.
- `AUTH_GITHUB_ALLOWED_ORGS` or `AUTH_GITHUB_ALLOWED_TEAMS` when the proxy forwards GitHub org or team membership.
- `AUTH_REQUIRED_DOMAIN` when every user from a specific email domain should be allowed.

## Logout Behavior

App logout only clears the local ServerMentor session cookie. If your reverse proxy, `oauth2-proxy`, or upstream IdP still has an active session, the user may be signed in again immediately on the next request unless that upstream session is also cleared.

## Troubleshooting

- If every request is rejected with `Proxy authentication required`, the proxy is not forwarding the headers the app expects.
- If requests are rejected with `Proxy authentication headers are only accepted from trusted proxies`, the proxy IP does not match `AUTH_PROXY_TRUSTED_PROXIES`.
- If login succeeds upstream but the app returns `Not authorized to access admin pages`, the user matched authentication but did not match your app-side allow rules.