# Strix Documentation

Source files for the Strix documentation site, published at **[docs.strix.ai](https://docs.strix.ai)** and built with [Mintlify](https://mintlify.com).

This folder is for user-facing product documentation (installation, CLI usage, integrations, and guides). It is separate from other docs in the repository:

| Location | Purpose |
|----------|---------|
| `docs/` (this folder) | Public docs site (Mintlify MDX) |
| [`CONTRIBUTING.md`](../CONTRIBUTING.md) | Code and project contribution guide |
| [`strix/skills/`](../strix/skills/) | Agent skill packages (see [`strix/skills/README.md`](../strix/skills/README.md)) |
| Tool-specific READMEs under `strix/tools/` | Internal developer notes for individual tools |

## Local preview

### Prerequisites

- [Node.js](https://nodejs.org/) 18.10 or later
- [Mintlify CLI](https://www.mintlify.com/docs/installation) (`mint`)

### Run the dev server

From the repository root:

```bash
npm i -g mint
cd docs
mint dev
```

The site is available at [http://localhost:3000](http://localhost:3000). Changes to MDX files reload automatically.

Without a global install:

```bash
cd docs
npx mint dev
```

Useful flags:

```bash
mint dev --no-open          # do not open a browser automatically
mint dev --port 3333        # use a custom port
```

Optional: run `mint login` to enable local search and the Mintlify assistant while previewing.

## Repository structure

```
docs/
├── docs.json              # Site config, navigation, theme, and metadata
├── images/                # Static assets (favicon, screenshots, etc.)
├── logo/                  # Brand assets
├── index.mdx              # Introduction / landing page
├── quickstart.mdx         # Getting started guide
├── contributing.mdx       # Contributor guide (also published on the site)
├── usage/                 # CLI, scan modes, and instructions
├── llm-providers/         # Provider setup guides
├── integrations/          # GitHub Actions and CI/CD
├── tools/                 # Sandbox toolkit reference
├── advanced/              # Configuration and skills
└── cloud/                 # Strix Cloud overview
```

Navigation and page order are defined in [`docs.json`](./docs.json). When you add or rename a page, update the `navigation` section so it appears in the sidebar.

## Writing and editing pages

### File format

- Pages are [MDX](https://mdxjs.com/) files (`.mdx`) with YAML frontmatter:

```mdx
---
title: "Page Title"
description: "Short summary used for SEO and link previews"
---

Your content here.
```

- Use Mintlify components where they help readability (`<Note>`, `<Tip>`, `<Warning>`, `<Steps>`, `<Card>`, `<ParamField>`, etc.). See the [Mintlify components reference](https://mintlify.com/docs/components).
- Prefer relative links for internal pages (for example `/usage/cli`) so links work in local preview and production.
- Place new images in `docs/images/` and reference them with root-relative paths (for example `/images/screenshot.png`).

### Common tasks

| Task | What to do |
|------|------------|
| Edit existing content | Update the relevant `.mdx` file and preview with `mint dev` |
| Add a new page | Create a `.mdx` file and register it in `docs.json` under the appropriate group |
| Add a new nav section | Add a group in `docs.json` → `navigation` |
| Document a new CLI flag or feature | Update `usage/cli.mdx` and any related guides (for example `usage/scan-modes.mdx`) |
| Document a new skill category | Update `advanced/skills.mdx`; skill source files live in `strix/skills/` |

### Style guidelines

- Match the tone of existing pages: direct, developer-focused, and practical.
- Lead with what the user needs to do, then add context and examples.
- Keep code samples copy-pasteable and tested when possible.
- Cross-link related pages instead of duplicating large sections (for example link to [LLM Providers](https://docs.strix.ai/llm-providers/overview) rather than re-listing every provider).

## Contributing documentation

Documentation contributions follow the same process as code:

1. [Fork](https://github.com/usestrix/strix/fork) the repository and branch from `main`.
2. Make your changes in `docs/` and verify them locally with `mint dev`.
3. Open a pull request with a clear description of what you changed and why.
4. Link to a related issue when one exists.

For broader contribution expectations (tests, code style, PR process), see:

- [`contributing.mdx`](./contributing.mdx) — published contributor guide
- [`CONTRIBUTING.md`](../CONTRIBUTING.md) — repository-level development setup

Questions? Open a [GitHub issue](https://github.com/usestrix/strix/issues) or ask in [Discord](https://discord.gg/strix-ai).

## Publishing

Production docs at [docs.strix.ai](https://docs.strix.ai) are deployed from this folder via Mintlify. After a docs PR is merged to the default branch, changes typically appear on the live site shortly after (exact timing depends on the Mintlify deployment configuration for the project).

## Troubleshooting

| Problem | Fix |
|---------|-----|
| `mint: command not found` | Install the CLI with `npm i -g mint`, or use `npx mint dev` |
| Page shows 404 in local preview | Confirm the file is listed in `docs.json` and you are running `mint dev` from the `docs/` directory |
| Port 3000 already in use | Run `mint dev --port 3333` (or another free port) |
| Windows path errors from Mintlify | See [Mintlify local development docs](https://www.mintlify.com/docs/installation) for platform-specific troubleshooting |
| Stale preview after edits | Restart `mint dev`; run `mint update` if the CLI itself seems outdated |

## Related links

- [Strix README](../README.md) — project overview, quick start, and feature summary
- [docs.strix.ai](https://docs.strix.ai) — live documentation
- [Strix Cloud](https://app.strix.ai) — hosted platform
- [Mintlify documentation](https://mintlify.com/docs) — MDX syntax, components, and deployment
