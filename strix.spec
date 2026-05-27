# -*- mode: python ; coding: utf-8 -*-

import sys
from pathlib import Path
from PyInstaller.utils.hooks import collect_data_files, collect_submodules

project_root = Path(SPECPATH)
strix_root = project_root / 'strix'

datas = []

for md_file in strix_root.rglob('skills/**/*.md'):
    rel_path = md_file.relative_to(project_root)
    datas.append((str(md_file), str(rel_path.parent)))

for jinja_file in strix_root.rglob('agents/**/*.jinja'):
    rel_path = jinja_file.relative_to(project_root)
    datas.append((str(jinja_file), str(rel_path.parent)))

for xml_file in strix_root.rglob('*.xml'):
    rel_path = xml_file.relative_to(project_root)
    datas.append((str(xml_file), str(rel_path.parent)))

for tcss_file in strix_root.rglob('*.tcss'):
    rel_path = tcss_file.relative_to(project_root)
    datas.append((str(tcss_file), str(rel_path.parent)))

datas += collect_data_files('textual')

datas += collect_data_files('tiktoken')
datas += collect_data_files('tiktoken_ext')

datas += collect_data_files('litellm')

datas += collect_data_files('agents', includes=['**/*.md', '**/*.jinja', '**/*.json'])

hiddenimports = [
    # Core dependencies
    'litellm',
    'litellm.llms',
    'litellm.llms.openai',
    'litellm.llms.anthropic',
    'litellm.llms.vertex_ai',
    'litellm.llms.bedrock',
    'litellm.utils',
    'litellm.caching',

    # Textual TUI
    'textual',
    'textual.app',
    'textual.widgets',
    'textual.containers',
    'textual.screen',
    'textual.binding',
    'textual.reactive',
    'textual.css',
    'textual._text_area_theme',

    # Rich console
    'rich',
    'rich.console',
    'rich.panel',
    'rich.text',
    'rich.markup',
    'rich.style',
    'rich.align',
    'rich.live',

    # Pydantic
    'pydantic',
    'pydantic.fields',
    'pydantic_core',
    'email_validator',

    # Docker
    'docker',
    'docker.api',
    'docker.models',
    'docker.errors',

    # HTTP/Networking
    'httpx',
    'httpcore',
    'requests',
    'urllib3',
    'certifi',

    # Jinja2 templating
    'jinja2',
    'jinja2.ext',
    'markupsafe',

    # XML parsing
    'xmltodict',
    'defusedxml',
    'defusedxml.ElementTree',

    # Syntax highlighting
    'pygments',
    'pygments.lexers',
    'pygments.styles',
    'pygments.util',

    # Tiktoken (for token counting)
    'tiktoken',
    'tiktoken_ext',
    'tiktoken_ext.openai_public',

    # Tenacity retry
    'tenacity',

    # CVSS scoring
    'cvss',

    # Strix modules
    'strix',
    'strix.interface',
    'strix.interface.main',
    'strix.interface.cli',
    'strix.interface.tui',
    'strix.interface.tui.app',
    'strix.interface.tui.history',
    'strix.interface.tui.live_view',
    'strix.interface.tui.messages',
    'strix.interface.tui.renderers',
    'strix.interface.tui.renderers.agent_message_renderer',
    'strix.interface.tui.renderers.agents_graph_renderer',
    'strix.interface.tui.renderers.base_renderer',
    'strix.interface.tui.renderers.finish_renderer',
    'strix.interface.tui.renderers.notes_renderer',
    'strix.interface.tui.renderers.proxy_renderer',
    'strix.interface.tui.renderers.registry',
    'strix.interface.tui.renderers.reporting_renderer',
    'strix.interface.tui.renderers.thinking_renderer',
    'strix.interface.tui.renderers.todo_renderer',
    'strix.interface.tui.renderers.user_message_renderer',
    'strix.interface.tui.renderers.web_search_renderer',
    'strix.interface.utils',
    'strix.agents',
    'strix.agents.factory',
    'strix.agents.prompt',
    'strix.config.models',
    'strix.core',
    'strix.core.agents',
    'strix.core.execution',
    'strix.core.inputs',
    'strix.core.paths',
    'strix.core.runner',
    'strix.core.sessions',
    'strix.report',
    'strix.report.dedupe',
    'strix.report.state',
    'strix.report.writer',
    'strix.runtime',
    'strix.runtime.backends',
    'strix.runtime.caido_bootstrap',
    'strix.runtime.docker_client',
    'strix.runtime.session_manager',
    'strix.telemetry',
    'strix.telemetry.logging',
    'strix.telemetry.posthog',
    'strix.tools',
    'strix.tools.agents_graph.tools',
    'strix.tools.finish.tool',
    'strix.tools.notes.tools',
    'strix.tools.proxy._calls',
    'strix.tools.proxy.tools',
    'strix.tools.python.tool',
    'strix.tools.reporting.tool',
    'strix.tools.thinking.tool',
    'strix.tools.todo.tools',
    'strix.tools.web_search.tool',
    'strix.skills',
]

hiddenimports += collect_submodules('litellm')
hiddenimports += collect_submodules('textual')
hiddenimports += collect_submodules('rich')
hiddenimports += collect_submodules('pydantic')
hiddenimports += collect_submodules('pygments')

excludes = [
    # Sandbox-only packages
    'playwright',
    'playwright.sync_api',
    'playwright.async_api',
    'IPython',
    'ipython',
    'libtmux',
    'pyte',
    'openhands_aci',
    'openhands-aci',
    'numpydoc',

    # Google Cloud / Vertex AI
    'google.cloud',
    'google.cloud.aiplatform',
    'google.api_core',
    'google.auth',
    'google.oauth2',
    'google.protobuf',
    'grpc',
    'grpcio',
    'grpcio_status',

    # Test frameworks
    'pytest',
    'pytest_asyncio',
    'pytest_cov',
    'pytest_mock',

    # Development tools
    'mypy',
    'ruff',
    'black',
    'isort',
    'pylint',
    'pyright',
    'bandit',
    'pre_commit',

    # Unnecessary for runtime
    'tkinter',
    'matplotlib',
    'numpy',
    'pandas',
    'scipy',
    'PIL',
    'cv2',
]

a = Analysis(
    ['strix/interface/main.py'],
    pathex=[str(project_root)],
    binaries=[],
    datas=datas,
    hiddenimports=hiddenimports,
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=excludes,
    noarchive=False,
    optimize=0,
)

pyz = PYZ(a.pure)

exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.datas,
    [],
    name='strix',
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=False,
    upx_exclude=[],
    runtime_tmpdir=None,
    console=True,
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
)
