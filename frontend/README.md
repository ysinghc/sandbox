# Sandbox Engine website

Static site for [sandbox.ysinghc.in](https://sandbox.ysinghc.in). No build step:
plain HTML, CSS, and a small amount of JavaScript, served by Cloudflare Workers
Static Assets from `frontend/`.

## Structure

```
frontend/
├── index.html            overview
├── download/index.html   release downloads and install
├── docs/index.html       documentation index
├── contribute/index.html contribution guide
├── security/index.html   disclosure and scope
├── 404.html
├── assets/
│   ├── style.css
│   ├── app.js
│   ├── favicon.svg
│   ├── og.png
│   └── fonts/            self-hosted IBM Plex (latin subset)
├── _headers              security and cache headers
├── robots.txt
└── sitemap.xml
```

## Preview

```sh
python3 -m http.server 8080 --directory frontend
```

Then open <http://localhost:8080>.

## Deploy

Deployment is configured by `../wrangler.jsonc`: the Worker is `sandbox-engine`,
its assets are this directory, and `sandbox.ysinghc.in` is a custom domain.

```sh
npx wrangler deploy
```

Cloudflare uploads the changed assets, applies `_headers`, serves `404.html`
for missing paths, and keeps the custom domain attached. No build command is
needed.

## Content sources

Copy and links follow the repository's `README.md`, `CONTRIBUTING.md`,
`CHANGELOG.md`, `docs/`, and `SYSTEM DESIGN.md`. Update this site when the
release version, download assets, or documentation layout changes.
