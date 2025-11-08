# Environment Variables

Strix supports the following environment variables for configuration:

## Required Variables

### `STRIX_LLM`
**Description:** Model name to use with litellm  
**Example:** `openai/gpt-4`, `anthropic/claude-3-opus`, `ollama/llama3.1`  
**Required:** Yes

### `LLM_API_KEY`
**Description:** API key for the LLM provider  
**Required:** Yes (except for local models like Ollama)  
**Example:** `sk-...`

## Optional Variables

### LLM Configuration

#### `LLM_API_BASE` / `OPENAI_API_BASE` / `LITELLM_BASE_URL` / `OLLAMA_API_BASE`
**Description:** Custom API base URL for local or self-hosted models  
**Example:** `http://localhost:11434` (Ollama), `http://localhost:1234/v1` (LMStudio)  
**Default:** Provider default

#### `STRIX_LLM_TIMEOUT`
**Description:** Timeout in seconds for LLM requests (warm-up and generation)  
**Example:** `600` (10 minutes)  
**Default:** `180` for cloud models, `300` for local models  
**Min value:** `30`

### Network Configuration

#### `STRIX_SOCKS_PROXY`
**Description:** Upstream SOCKS proxy for all HTTP requests  
**Format:** `socks5://host:port` or `socks4://host:port`  
**Example:** `socks5://127.0.0.1:9050` (Tor), `socks5://proxy.example.com:1080`  
**Default:** None

### Proxy/Caido Integration

#### `CAIDO_PORT`
**Description:** Port for Caido proxy GraphQL API  
**Default:** `56789`

#### `CAIDO_API_TOKEN`
**Description:** API token for Caido authentication  
**Default:** None

### Web Search

#### `PERPLEXITY_API_KEY`
**Description:** API key for Perplexity AI web search (enables real-time research)  
**Example:** `pplx-...`  
**Default:** None

## Usage Examples

### Cloud Provider (OpenAI)
```powershell
# PowerShell
$env:STRIX_LLM = "openai/gpt-4"
$env:LLM_API_KEY = "sk-..."
```

```bash
# Bash
export STRIX_LLM="openai/gpt-4"
export LLM_API_KEY="sk-..."
```

### Local Model (Ollama)
```powershell
# PowerShell
$env:STRIX_LLM = "ollama/llama3.1"
$env:LLM_API_BASE = "http://localhost:11434"
$env:STRIX_LLM_TIMEOUT = "600"  # 10 minutes for slower local models
```

```bash
# Bash
export STRIX_LLM="ollama/llama3.1"
export LLM_API_BASE="http://localhost:11434"
export STRIX_LLM_TIMEOUT="600"
```

### With SOCKS Proxy (Tor)
```powershell
# PowerShell
$env:STRIX_LLM = "openai/gpt-4"
$env:LLM_API_KEY = "sk-..."
$env:STRIX_SOCKS_PROXY = "socks5://127.0.0.1:9050"
```

```bash
# Bash
export STRIX_LLM="openai/gpt-4"
export LLM_API_KEY="sk-..."
export STRIX_SOCKS_PROXY="socks5://127.0.0.1:9050"
```

### Complete Setup with All Features
```powershell
# PowerShell
$env:STRIX_LLM = "anthropic/claude-3-opus"
$env:LLM_API_KEY = "sk-ant-..."
$env:STRIX_LLM_TIMEOUT = "300"
$env:PERPLEXITY_API_KEY = "pplx-..."
$env:STRIX_SOCKS_PROXY = "socks5://proxy.example.com:1080"
$env:CAIDO_PORT = "56789"
$env:CAIDO_API_TOKEN = "your-caido-token"
```

## Persistent Configuration

### Windows (PowerShell)
```powershell
# Set permanently (requires restart)
[System.Environment]::SetEnvironmentVariable('STRIX_LLM', 'openai/gpt-4', 'User')
[System.Environment]::SetEnvironmentVariable('LLM_API_KEY', 'sk-...', 'User')

# Or use setx (simpler but requires new terminal)
setx STRIX_LLM "openai/gpt-4"
setx LLM_API_KEY "sk-..."
```

### Linux/macOS (Bash/Zsh)
```bash
# Add to ~/.bashrc or ~/.zshrc
echo 'export STRIX_LLM="openai/gpt-4"' >> ~/.bashrc
echo 'export LLM_API_KEY="sk-..."' >> ~/.bashrc
source ~/.bashrc
```

## Troubleshooting

### Timeout Issues with Local Models
If you're experiencing timeouts with Ollama or other local models:
```powershell
$env:STRIX_LLM_TIMEOUT = "900"  # 15 minutes
```

### SOCKS Proxy Not Working
Ensure your SOCKS proxy is running and accessible:
```powershell
# Test with curl
curl --socks5 127.0.0.1:9050 https://check.torproject.org
```

### Ollama Connection Issues (Windows)
```powershell
# Ensure Ollama is running
ollama serve

# Check if model is available
ollama list

# Pull model if needed
ollama pull llama3.1

# Verify API is accessible
curl http://localhost:11434/api/tags
```
