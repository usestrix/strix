## Fix: Server Connectivity Issue

This document explains how to resolve Docker and LLM connection issues when running Strix locally on macOS.

### Steps:
1. Install Docker and Colima
2. Start Docker daemon with `colima start`
3. Install Ollama and pull Llama3 model
4. Export environment variables:
   ```bash
   export STRIX_LLM='ollama/llama3'
   export LLM_API_BASE='http://localhost:11434'
   ```
5. Run:
   ```bash
   poetry run strix --target <repo-url>
   ```

Verified on MacBook M2. ✅

