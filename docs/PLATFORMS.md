# Platform Configuration

The web portal is the source of truth for platform settings.

## Stored settings

Each platform can store:

- API key / token
- base URL
- enabled state

These are saved server-side in SQLite, not in `config/platforms.toml`.

## Supported platform keys

- `OPENAI_API_KEY`
- `THEHIVE_API_KEY`
- `CORTEX_API_KEY`
- `WAZUH_API_TOKEN`
- `VIRUSTOTAL_API_KEY`
- `ABUSEIPDB_API_KEY`
- `SHODAN_API_KEY`
- `URLSCAN_API_KEY`
- `HYBRID_ANALYSIS_API_KEY`
- `MISP_API_KEY`

## Supported base URLs

- `THEHIVE_URL`
- `CORTEX_URL`
- `WAZUH_URL`
- `WAZUH_INDEXER_URL`
- `VIRUSTOTAL_URL`
- `ABUSEIPDB_URL`
- `SHODAN_URL`
- `URLSCAN_URL`
- `HYBRID_ANALYSIS_URL`
- `MISP_URL`

## How connection tests work

The credentials page includes a **Test Connections** button.

When clicked, the web app runs server-side checks for every configured platform and returns JSON with one result per platform:

- `ok`
- `error`
- `skipped`

The frontend shows those results inline with a green tick, red cross, or grey dash.

## Runtime config generation

Before a run starts, the web app regenerates `config/platforms.toml` from database state so the orchestrator still reads TOML, but the TOML file is always current.

## Operational notes

- API keys are never shown again after saving
- Base URLs are plain-text fields
- Connection tests use short timeouts and catch errors per platform
- Platform settings should be edited in the web portal, not by hand-editing TOML
