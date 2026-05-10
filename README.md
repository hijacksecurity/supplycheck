# supplycheck

> Cross-ecosystem package supply chain risk scorer.
> A small supply chain utility by [Hijack Security](https://www.hijacksecurity.com).

Look up any package on **npm**, **PyPI**, **Maven Central**, **Go**, or **NuGet** and get a one-page risk report combining live registry metadata with [OSV.dev](https://osv.dev) advisories — including confirmed-malicious packages from the [OpenSSF Malicious Packages dataset](https://github.com/ossf/malicious-packages).

## Highlights

- **Single-package lookup** with a letter grade and prioritized findings
- **Lockfile / multi-package scan** — paste a `package.json`, `package-lock.json`, `yarn.lock`, `pnpm-lock.yaml`, `requirements.txt`, `Pipfile`, `Pipfile.lock`, `pyproject.toml`, `go.mod`, `pom.xml`, or `.csproj` and scan every dependency in parallel
- **Version-aware** — findings are split into "affects current version" and "historical advisories" so the grade reflects current risk, not history
- **Confirmed-malicious detection** — `MAL-*` IDs from OpenSSF plus keyword-matched malware advisories trigger an explicit "do not install" warning
- **Cross-ecosystem typosquat detection** — Levenshtein distance vs popular-package baselines, with download-threshold suppression to cut false positives
- **Shareable URL state** — every result has a permalink (`#eco=npm&pkg=lodash`) you can paste into incident threads
- **Markdown / JSON export** — copy a clean report into Jira, Slack, GitHub PR comments, or audit logs
- **No backend, no tracking** — every fetch happens in the user's browser. Hosted as a single static HTML file.

## Try it

- **Production:** https://supplycheck.hijacksecurity.com
- Single package: append `#eco=npm&pkg=lodash` to the URL
- Lockfile scan: switch to "Lockfile / multi-package scan" tab and paste a manifest

### Try these

| Query | What you'll see |
|---|---|
| `lodash` (npm) | Clean baseline. Grade A, ~10 historical advisories all properly tagged with fix versions. |
| `loadsh` (npm) | Typosquat detection — distance 2 from `lodash`. |
| `event-stream` (npm) | Republished safe version (4.0.1). The infamous flatmap-stream advisory is in historical. |
| `ua-parser-js` (npm) | Post-incident clean version. Embedded-malware GHSA correctly stays in historical. |
| `com.fasterxml.jackson.core:jackson-databind` (Maven) | 0 current findings, 60+ historical CVEs — perfect demo of the version-aware split. |
| `github.com/gin-gonic/gin` (Go) | Clean Go baseline; positive checksum-database signal. |

## Data sources

- **Registries:** registry.npmjs.org, pypi.org, [deps.dev](https://deps.dev) (Maven, Go), api.nuget.org
- **Download stats:** api.npmjs.org
- **Vulnerabilities & malicious packages:** [OSV.dev](https://osv.dev) — aggregates GHSA, OpenSSF Malicious Packages, PyPA, Go vulnerability database, RustSec, and more

All requests are made directly from the user's browser.

## Architecture

Single-file static site. ~1700 lines of HTML/CSS/vanilla JS. No build step, no dependencies, no backend.

```
supplycheck/
├── index.html       # the entire app
├── vercel.json      # security headers + routing
├── README.md
└── LICENSE
```

Per-ecosystem adapters share a normalized package shape (`fetchPkg(name) → NormalizedPackage`, `analyze(pkg) → Finding[]`). Universal heuristics (age, maintainer count, repo presence, typosquat) run on every lookup; ecosystem-specific signals layer on top.

## Findings catalog

**Universal**
- Newly-published / fairly-young package
- Stale (latest > 2 years old)
- Single maintainer
- Missing source repository
- Typosquat distance vs ecosystem top-N (suppressed when query is itself popular)
- Non-ASCII / homoglyph in name

**npm**
- `preinstall` / `install` / `postinstall` lifecycle scripts
- Sigstore provenance attestation present / missing
- `bin` entries colliding with system binaries
- Package version deprecated

**PyPI**
- Source distribution only (no wheel) — install runs setup.py
- PEP 740 attestations present / missing
- Yanked release
- Self-declared early development status

**Maven Central**
- Shallow groupId (non-reverse-DNS)
- `com.github.<user>` namespace mismatch with declared repo

**Go modules**
- Module-path host outside the well-known set
- Positive: protected by Go checksum database

**NuGet**
- Unlisted version
- Deprecated package
- Vulnerability advisories present in NuGet catalog

**OSV.dev** (cross-ecosystem)
- `MAL-*` IDs → `critical` + "DO NOT INSTALL"
- Keyword-detected malware (`embedded malware`, `malicious code`, `backdoor`, `crypto-stealer`, `info-stealer`, `protestware`, ...) → `critical`
- Standard advisories with severity mapped from OSV CVSS scores
- Removed-from-registry packages with malicious history are still flagged

## Run locally

```sh
python3 -m http.server 3000
# then open http://localhost:3000
```

Or any other static file server. Nothing to install.

## Deployment

Hosted on Vercel as a static site:

| Branch | Environment | URL |
|---|---|---|
| `main` | Production | https://supplycheck.hijacksecurity.com |
| `test` | Staging / preview | auto-generated by Vercel |

To deploy:

1. Push this repo to GitHub (`hijacksecurity/supplycheck`).
2. In Vercel, **Add New → Project** and import the repo.
3. Framework preset: **Other** (static). Build command: leave blank. Output directory: `.` (root).
4. Set **Production Branch** to `main` in **Settings → Git**.
5. Push to `test` to get an auto-generated preview URL with a stable slug like `supplycheck-git-test-hijacksecurity.vercel.app`.

Security headers (X-Frame-Options, X-Content-Type-Options, Referrer-Policy, Permissions-Policy) are applied via `vercel.json`.

## License

[MIT](LICENSE) — use it, fork it, embed it, build on it.

## Contributing

Issues and PRs welcome at [hijacksecurity/supplycheck](https://github.com/hijacksecurity/supplycheck).

Reasonable additions:

- More signals per ecosystem (e.g. PyPI maintainer 2FA status when surfaced, RubyGems / crates.io adapters)
- Nightly refresh of the typosquat top-N lists via a small build script
- An SVG badge endpoint (`/badge?eco=npm&pkg=lodash` → grade SVG) for embedding in READMEs

## Disclaimer

`supplycheck` is a triage aid, not a verdict. Findings are heuristic — high severity ≠ malicious, info ≠ safe. Use it to focus manual review and pair it with your own threat modelling. The `MAL-*` and keyword-matched malware findings are ground-truth from public datasets, but no automated tool catches every supply chain attack.

Built by [Hijack Security](https://www.hijacksecurity.com).
