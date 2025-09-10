# aibom-tools

A CLI tool for generating AI Bill of Materials (AI-BOM) using the Snyk API.

## Installation

### Using uvx (recommended)

```bash
uv tool install git+https://github.com/dylansnyk/aibom-tools
uvx aibom-tools scan
```

### Run locally

```bash
git clone https://github.com/dylansnyk/aibom-tools
cd aibom-tools
uv run aibom_tools scan
```

## Upgrading

```bash
uv tool upgrade aibom-tools
```

## Configuration

The tool requires Snyk API credentials. You can provide them via:

1. Environment variables (recommended)
2. Command line options
3. `.env` file in your project directory

### Environment Variables

```bash
export SNYK_API_TOKEN="your-api-token-here"
export SNYK_ORG_ID="your-org-id-here"
export SNYK_API_URL="https://api.snyk.io"  # Optional, defaults to public API
```

### .env File

Create a `.env` file in your project directory:

```bash
SNYK_API_TOKEN=your-api-token-here
SNYK_ORG_ID=your-org-id-here
SNYK_API_URL=https://api.snyk.io
```

## Usage

### Basic Scan Command

```bash
# Scan all targets in your Snyk org
uvx aibom-tools scan

# Filter only for ML Models
uvx aibom-tools scan --include 'ML Model'

# Run from git repo
uvx --from git+https://github.com/dylansnyk/aibom-tools scan
```

### Output to JSON file

```bash
# Specify path to output file
uvx aibom-tools scan --output output.json
```

### Command Line Options

```zsh
# Global options
➜  aibom-tools git:(main) ✗ uv run aibom-tools --help         
Usage: aibom-tools [OPTIONS] COMMAND [ARGS]...

  aibom-tools: CLI tool for generating AI Bill of Materials using Snyk API

  This tool helps you create AI BOMs for your projects using Snyk's AI-BOM
  API.

Options:
  --version         Show the version and exit.
  --api-token TEXT  Snyk API token (can also be set via SNYK_API_TOKEN env
                    var)
  --org-id TEXT     Snyk Organization ID (can also be set via SNYK_ORG_ID env
                    var)
  --api-url TEXT    Snyk API base URL (defaults to https://api.snyk.io)
  --debug           Enable debug logging
  --help            Show this message and exit.

Commands:
  scan  Create a new AI-BOM scan
```
```zsh
# Scan options
➜  aibom-tools git:(main) ✗ uv run aibom-tools scan --help
Usage: aibom-tools scan [OPTIONS]

  Create a new AI-BOM scan

  This command triggers a scan of all targets in the given Snyk organization.

Options:
  -o, --output PATH   Output file path for AI-BOMs
  -i, --include TEXT  Comma-separated list of AI component types to include in
                      the summary (e.g., 'ML Model,Application,Library')
  --help              Show this message and exit.
```

### Help

```bash
# General help
uvx aibom-tools --help

# Scan command help
uvx aibom-tools scan --help
```

## Output Format

Using `--output` or `-o` can be used to output a JSON file. The AI-BOM results are returned in the standard Snyk API JSON format:

```json
{
    "all_aibom_data": [
        {
            "target_name": "repo_org/name",
            "aibom_data": {
              ...
            }
        }
    ]
}
```