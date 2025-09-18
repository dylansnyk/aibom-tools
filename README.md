# aibom-tools

A CLI tool for generating AI Bill of Materials (AI-BOM) using the Snyk API.

## Installation

### Using uvx (recommended)

```bash
export SNYK_ORG_ID="your-org-id-here"
export SNYK_API_TOKEN="your-api-token-here"

uv tool install git+https://github.com/dylansnyk/aibom-tools
uvx aibom-tools scan
```

### Run locally

```bash
git clone https://github.com/dylansnyk/aibom-tools
cd aibom-tools
uv run aibom-tools scan
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

# One of org id or group id is required. If both are present the group id will be used
export SNYK_ORG_ID="your-org-id-here"
export SNYK_GROUP_ID="your-group-id-here"

# Optional, defaults to public API
export SNYK_API_URL="https://api.snyk.io"  
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

# Optionally, instead of setting environment variables, you can pass API token and org id as command line options
uvx aibom-tools \
    --api-token your-api-token-here \
    --org-id your-org-id-here \
    scan 
```

### Specify AI Components to Include

```bash
# Filter only for ML Models
uvx aibom-tools scan --include 'ML Model'

# Filter multiple components
uvx aibom-tools scan --include 'ML Model,Application,Library'
```

Available components:
- Application
- ML Model
- Dataset
- Library
- Agent
- MCP Client
- MCP Server
- MCP Resource
- Tool
- Service

### Create HTML file output

```bash
# Specify path to output file
uvx aibom-tools scan --html output.html
```

### Output to JSON file

```bash
# Specify path to output file
uvx aibom-tools scan --json output.json
```

### Output Grouping

You can control how the output is grouped using the `--group-by` parameter:

```bash
# Group by AI component (default behavior)
uvx aibom-tools scan --group-by component

# Group by repository - shows each repository with its AI components grouped together
uvx aibom-tools scan --group-by repo

# Generate HTML report grouped by repository
uvx aibom-tools scan --group-by repo --html report.html
```

Available grouping options:
- `component` (default): Groups output by AI component name
- `repo`: Groups output by repository, showing each repository with its AI components listed underneath

### Policy File Validation

You can use a YAML policy file to define forbidden AI models that should be flagged during the scan:

```bash
# Use policy file to validate against forbidden models
uvx aibom-tools scan --policy-file policy.yaml
```

#### Policy File Format

Create a YAML file with the following structure:

```yaml
reject:
  - claude-3-5-sonnet-20240620
  - gpt-3.5-turbo
  - gpt-4
  - llama-2-7b
```

An example policy file (`policy-example.yaml`) is included in the repository for reference.


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
