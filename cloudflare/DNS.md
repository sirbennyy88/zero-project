# Domain: zero.propulse.tech

Canonical domain for Zero Project is **zero.propulse.tech** (propulse.tech DNS lives on Cloudflare).
The site itself stays hosted on GitHub Pages (`sirbennyy88.github.io/zero-project/`); this is just a
custom-domain CNAME pointed at that Pages site.

## DNS record to create (in the propulse.tech zone, Cloudflare dashboard)

| Field | Value |
|---|---|
| Type | `CNAME` |
| Name | `zero` |
| Target | `sirbennyy88.github.io` |
| Proxy status | **DNS only** (grey cloud) |
| TTL | Auto |

**Why DNS-only (grey cloud):** GitHub Pages issues and validates its own TLS certificate for a custom
domain via an HTTP-01 / DNS challenge against the apex resolution of the CNAME target. If the record is
proxied (orange cloud), Cloudflare's edge IPs stand in front of the domain and GitHub's certificate
issuance and automatic HTTPS enforcement can fail or get stuck in a "pending" state — because GitHub is
no longer able to see the real request or issue a certificate against a name that resolves to Cloudflare
by default. DNS-only is the supported path.

**Trade-off if you want it proxied anyway:** Cloudflare can proxy the domain (orange cloud) if you first
set the zone's **SSL/TLS mode to Full** (not Full-strict, since GitHub's cert is issued for the
`.github.io` name, not custom domains, in some edge cases) and accept that GitHub Pages' own
custom-domain HTTPS certificate provisioning may not complete or may need to be re-triggered after
un-proxying temporarily for the initial validation. Cloudflare's own edge certificate then serves
visitors, and Cloudflare proxies through to GitHub Pages over HTTPS. This gets you Cloudflare's WAF/cache
in front of the tracker, at the cost of a fragile initial setup and losing GitHub's own cert/redirect
management. For a simple static tracker, DNS-only is the safer default — **use DNS-only unless you
specifically want Cloudflare's edge in front of GitHub Pages.**

## Status as of 2026-09-07

`Resolve-DnsName zero.propulse.tech` returned **no record** — the CNAME above has not been created yet.
The site therefore remains live at `https://sirbennyy88.github.io/zero-project/` for now, and all
canonical/OG URLs in this repo were left pointing at the old `zero.peries.ca` domain's *replacement*,
`https://zero.propulse.tech/`, in anticipation of the cutover (see note below). `zero.peries.ca` will
redirect once the new domain is confirmed live.

## Follow-up once the DNS record above exists and has propagated

1. Add a `CNAME` file to the repo root containing exactly:
   ```
   zero.propulse.tech
   ```
2. Set the GitHub Pages custom domain via the API:
   ```bash
   gh api -X PUT repos/sirbennyy88/zero-project/pages -f cname=zero.propulse.tech
   ```
3. Wait for GitHub to show "DNS check successful" and issue the certificate (Settings → Pages in the
   repo, or `gh api repos/sirbennyy88/zero-project/pages` and check `https_certificate.state`).
4. Once `https_certificate.state` is `approved`, GitHub will auto-redirect HTTP → HTTPS on the custom
   domain.

## Verifying

```powershell
Resolve-DnsName zero.propulse.tech
gh api repos/sirbennyy88/zero-project/pages
```
