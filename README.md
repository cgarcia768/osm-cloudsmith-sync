# OpenSourceMalware → Cloudsmith EPM Sync

Automatically syncs verified malicious packages and container images from [OpenSourceMalware.com](https://opensourcemalware.com) into a [Cloudsmith Enterprise Policy Manager (EPM)](https://cloudsmith.com/product/enterprise-policy-manager) blocklist policy. Runs hourly via GitHub Actions.

## What it does

1. Fetches all verified malicious threats (packages + container images) across all severity levels from the OpenSourceMalware.com API
2. Parses package names, ecosystems (npm, PyPI, Docker Hub, etc.), and version info
3. Generates a Rego policy in Cloudsmith's `format:name:version` blocklist format
4. Patches the policy into your Cloudsmith EPM "Exact Blocklist" via the REST API
5. Tracks state between runs and only updates the policy when new threats are added or removed

## Supported ecosystems

| OpenSourceMalware | Cloudsmith format |
|---|---|
| npm | npm |
| PyPI | python |
| Docker Hub | docker |
| Maven | maven |
| NuGet | nuget |
| RubyGems | ruby |
| Go | go |
| Cargo | cargo |

## Setup

### 1. Create the EPM policy in Cloudsmith

Create an "Exact Blocklist" policy in your Cloudsmith workspace via the UI or API. Note the `slug_perm` from the response — this is your policy identifier.

### 2. Add a quarantine action

Attach a `SetPackageState` action to the policy so matched packages are automatically quarantined:

```bash
curl -X POST "https://api.cloudsmith.io/v2/workspaces/$CLOUDSMITH_WORKSPACE/policies/$POLICY_SLUG/actions/" \
  -H "Content-Type: application/json" \
  -H "X-Api-Key: $CLOUDSMITH_API_KEY" \
  -d '{
    "action_type": "SetPackageState",
    "package_state": "Quarantined",
    "precedence": 1
  }'
```

### 3. Configure GitHub secrets

Add the following secrets to this repository (Settings → Secrets and variables → Actions):

| Secret | Description |
|---|---|
| `CLOUDSMITH_API_KEY` | Your Cloudsmith API key |
| `CLOUDSMITH_WORKSPACE` | Your Cloudsmith workspace slug |
| `CLOUDSMITH_POLICY_SLUG` | The `slug_perm` of your Exact Blocklist policy |

### 4. Run

The workflow runs automatically every hour at :15 past. You can also trigger it manually from the Actions tab.

## How the Rego policy works

The generated policy uses two blocklists:

- **Versioned blocklist** — exact `format:name:version` triplets for threats where specific versions are known (e.g. `npm:probity:1.2.5`)
- **Wildcard blocklist** — `format:name` pairs that block all versions when no specific version is listed (e.g. `docker:021982/xmrig`)

When a package enters a Cloudsmith repository, the EPM engine evaluates it against both lists. If matched, the configured action (quarantine) is applied automatically.

## Running locally

```bash
pip install requests

export CLOUDSMITH_API_KEY=<your-key>
export CLOUDSMITH_WORKSPACE=<your-workspace>
export CLOUDSMITH_POLICY_SLUG=<your-policy-slug>

python sync_osm_to_cloudsmith.py
```

## Data sources

- **Packages:** [OpenSourceMalware.com](https://opensourcemalware.com/?type=package) — npm, PyPI, and other registry malware
- **Containers:** [OpenSourceMalware.com](https://opensourcemalware.com/?type=container) — malicious Docker Hub images

## License

MIT
