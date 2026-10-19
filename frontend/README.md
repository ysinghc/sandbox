# Sandbox Engine website

Static site for [sandbox.ysinghc.in](https://sandbox.ysinghc.in). No build step:
plain HTML, CSS, and a small amount of JavaScript, served by Cloudflare Pages.

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

The Pages project is `sandbox-engine`; `sandbox.ysinghc.in` is its custom domain.

```sh
npx wrangler pages deploy frontend \
  --project-name sandbox-engine \
  --branch master \
  --commit-dirty=true
```

Or push to `master` after connecting the project to GitHub in the Cloudflare
dashboard. The site has no build command and uses `frontend` as its root.

## Content sources

Copy and links follow the repository's `README.md`, `CONTRIBUTING.md`,
`CHANGELOG.md`, `docs/`, and `SYSTEM DESIGN.md`. Update this site when the
release version or documentation layout changes.
