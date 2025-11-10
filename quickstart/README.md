# Strix Quickstart Template

> Purpose: Minimal local demo to run Strix against a tiny Flask app using Docker Compose.

This directory contains a small Flask service and container configs to quickly try Strix locally.

## Prerequisites
- Docker and Docker Compose
- Python optional (not required if using Docker)

## Run with Docker Compose
```bash
docker compose up --build
```
- App will be available at http://localhost:5000
- Health check: http://localhost:5000/health

## Run Strix against the local app
From the repository root:
```bash
strix --target ./quickstart/app
```
- On first run, Strix will set up its environment, parse the target, and begin analysis with default modules.
- You should see it enumerate the Flask routes and perform basic checks.

## Stop
```bash
docker compose down
```
