# Internet Relay via GitHub Actions

A censorship-circumvention relay that runs on **GitHub Actions** — no VPS required.

## How it works

1. You write a request (URL + method + headers) as a JSON file in `requests/`
2. You trigger the `relay.yml` workflow via `gh workflow run` or the GitHub API
3. A GitHub-hosted runner (with full internet) fetches your URL
4. The response (headers + body) is written to `responses/`
5. You read the response via `raw.githubusercontent.com` or the GitHub API

Both `api.github.com` and `raw.githubusercontent.com` must be accessible from your location.

## Usage

```bash
# 1. Create a request
echo '{"url":"https://httpbin.org/get","method":"GET"}' > requests/test.json

# 2. Trigger the workflow
gh workflow run relay.yml -f request_id=test

# 3. Wait ~30-60 seconds, then read the result
curl https://raw.githubusercontent.com/<OWNER>/internet-relay/main/responses/test.txt
```

## Why GitHub Actions?

- **Free** — public repos get unlimited Actions minutes
- **24/7 via handoff** — see bot.yml pattern in blackout-internet-downloader
- **No VPS** — no billing, no server management
- **Full internet** — runners have unrestricted outbound access
- **Accessible** — api.github.com and raw.githubusercontent.com are widely reachable
