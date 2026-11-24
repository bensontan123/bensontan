# Deploying ARTEX to a real host (Fly.io or Railway)

ARTEX **cannot** run on Vercel/Netlify/Cloudflare Pages. It is a stateful Go
daemon (UI + API + SSE on `:8787`, a traffic-recording proxy on `:8788`, 3
background workers, long-running autonomous jobs) that needs **PostgreSQL** and
a **persistent disk**. Serverless platforms give you none of those, which is
why a Vercel deploy shows *"no backend service"* — only the static frontend
ships, with no Go server behind it.

Deploy it to a container/VM host instead. Two good, low-friction options below.
Both use the prebuilt image **`ghcr.io/jiwoochris/artex-global:latest`** plus a
managed Postgres.

## Before you start

You need these values ready:

| Variable | Required | What it is |
|---|---|---|
| `ARTEX_PG_DSN` | yes | Postgres connection string, e.g. `postgres://user:pass@host:5432/artex?sslmode=disable` |
| `ARTEX_ADMIN_PASSWORD` | yes* | Admin password, 8+ chars. Skips the `/setup` token flow. |
| `ANTHROPIC_API_KEY` | for scanning | Claude API key. Without it the engine stays idle and no scan runs. |
| `ARTEX_LANG` | optional | `en` / `ko` / `zh` / `es` / `ja` (default `en`). |

\* If you omit `ARTEX_ADMIN_PASSWORD`, ARTEX prints a one-time **setup token**
to the logs on first boot; open `/setup` and paste it to create the password.

Two rules that matter on any host:

- **Expose only `8787`.** Never route `8788` (the MITM traffic proxy) to the
  public internet.
- **Don't buffer the response.** ARTEX streams a live activity feed over SSE on
  the same origin. Fly and Railway's proxies stream fine out of the box; if you
  put your own Nginx in front, set `proxy_buffering off;`.

---

## Option A — Fly.io

Install the CLI and sign in: `curl -L https://fly.io/install.sh | sh`, then `fly auth login`.

```bash
cd deploy
# 1) Edit fly.toml: set a unique `app` name and your `primary_region`.

# 2) Create the app (don't deploy yet) and a managed Postgres.
fly apps create APP_NAME
fly postgres create --name APP_NAME-db --region sin --initial-cluster-size 1 --vm-size shared-cpu-1x --volume-size 1
fly postgres attach APP_NAME-db --app APP_NAME        # sets a DATABASE_URL secret

# 3) ARTEX reads ARTEX_PG_DSN, not DATABASE_URL. Mirror it (add sslmode=disable
#    for Fly's private-network Postgres). Grab the URL Fly just printed on attach,
#    or from `fly postgres` docs, then:
fly secrets set --app APP_NAME \
  ARTEX_PG_DSN="postgres://USER:PASS@APP_NAME-db.flycast:5432/APP_NAME?sslmode=disable" \
  ARTEX_ADMIN_PASSWORD="choose-a-strong-8plus-char-password" \
  ANTHROPIC_API_KEY="sk-ant-..."

# 4) Persistent /app/data volume (keeps jwt.key stable across restarts).
fly volumes create artex_data --app APP_NAME --region sin --size 1

# 5) Deploy the image defined in fly.toml.
fly deploy --app APP_NAME

# 6) Open it.
fly open --app APP_NAME        # https://APP_NAME.fly.dev
fly logs  --app APP_NAME       # watch for the setup token if you skipped the admin password
```

Notes:
- `auto_stop_machines` is **off** in `fly.toml` on purpose — autonomous scans and
  the SSE feed must not be suspended mid-run.
- Bump memory to 2 GB (`shared-cpu-2x`) in `fly.toml` for heavier scans.

---

## Option B — Railway

All dashboard-driven; no Dockerfile build needed (deploy the published image).

1. **New Project** → add a **PostgreSQL** database plugin. It exposes
   `DATABASE_URL` / `PGHOST` / etc. as referenceable variables.
2. **New** → **Deploy from Docker Image** →
   `ghcr.io/jiwoochris/artex-global:latest`.
3. On that service → **Variables**, add:
   - `ARTEX_PG_DSN` = `${{Postgres.DATABASE_URL}}` (append `?sslmode=disable` if
     Railway's URL doesn't already request SSL correctly for your plan)
   - `ARTEX_ADMIN_PASSWORD` = a strong 8+ char password
   - `ANTHROPIC_API_KEY` = `sk-ant-...`
   - `ARTEX_LANG` = `en`
4. **Settings → Networking** → **Generate Domain**, and set the **target port to
   `8787`**. Do **not** expose 8788.
5. **Settings → Volumes** → add a volume mounted at **`/app/data`**.
6. Deploy, then open the generated `*.up.railway.app` URL. If you skipped
   `ARTEX_ADMIN_PASSWORD`, check **Deploy Logs** for the one-time setup token and
   finish at `/setup`.

`railway.json` in this folder documents the start command, health check and
target port if you prefer config-as-code.

---

## First login

1. Open the URL. If you set `ARTEX_ADMIN_PASSWORD`, log in as user **`ARTEX`**
   with that password. Otherwise complete `/setup` with the token from the logs.
2. Confirm the engine is active: the LLM/engine status should not say
   *"no LLM provider configured"*. If it does, `ANTHROPIC_API_KEY` isn't set.
3. Create a task scoped to a target **you are authorized to test**, and run it.

## Security

- Put it behind the platform's auth/SSO or at least a strong admin password —
  this is an offensive tool; an open instance is a liability.
- Keep it scoped to authorized targets only. ARTEX's own LICENSE/notice says the
  same.
- Rotate `ANTHROPIC_API_KEY` if the instance is ever shared or exposed.
