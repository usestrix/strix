"""Instruction presets offered by the "new scan" wizard.

Each one only pre-fills the instruction box and the scan mode; the operator can
edit both before launching. ``{target}`` is replaced by the chosen target in the
UI. An empty instruction means Strix's own default methodology.
"""

from __future__ import annotations

from typing import Any


INSTRUCTION_TEMPLATES: list[dict[str, Any]] = [
    {
        "id": "full",
        "name": "Pentest completo",
        "description": "Metodología por defecto de Strix: reconocimiento, mapeo y explotación.",
        "scan_mode": "standard",
        "instruction": "",
    },
    {
        "id": "owasp",
        "name": "OWASP Top 10",
        "description": "Recorre las 10 categorías y declara la cobertura de cada una.",
        "scan_mode": "standard",
        "instruction": (
            "Realiza una evaluación sistemática del OWASP Top 10 (2021) sobre {target}. "
            "Para cada categoría (de A01 a A10) indica qué probaste, con qué endpoints "
            "y el resultado. "
            "Reporta como vulnerabilidad solo lo que confirmes con una PoC funcional; "
            "si una categoría no aplica o no se pudo probar, dilo explícitamente en el informe."
        ),
    },
    {
        "id": "targeted",
        "name": "Prueba dirigida",
        "description": "Una sola vulnerabilidad en un endpoint concreto. Rápida y barata.",
        "scan_mode": "quick",
        "instruction": (
            "Prueba únicamente <VULNERABILIDAD> en <MÉTODO> <ENDPOINT> (parámetro <CAMPO>) de "
            "{target}. No pruebes nada más. Confírmala con una PoC, repórtala como vulnerabilidad "
            "y termina en cuanto esté confirmada."
        ),
    },
    {
        "id": "authz",
        "name": "Autenticación y autorización",
        "description": "Login, sesiones, JWT, IDOR/BOLA y escalada de privilegios.",
        "scan_mode": "standard",
        "instruction": (
            "Céntrate en autenticación y autorización de {target}: bypass de login, gestión de "
            "sesión y tokens (JWT: firma, alg none, expiración), recuperación de contraseña, "
            "IDOR/BOLA entre usuarios y escalada horizontal y vertical de privilegios. "
            "Crea al menos dos usuarios de prueba si el registro está abierto y cruza sus recursos."
        ),
    },
    {
        "id": "injection",
        "name": "Inyecciones",
        "description": "SQLi, NoSQLi, inyección de comandos, SSTI y XSS.",
        "scan_mode": "standard",
        "instruction": (
            "Busca vulnerabilidades de inyección en {target}: SQL, NoSQL, comandos del sistema, "
            "SSTI y XSS (reflejado, almacenado y DOM). Prioriza formularios de login, búsqueda y "
            "cualquier parámetro que llegue a una consulta. Confirma cada hallazgo con una PoC."
        ),
    },
    {
        "id": "api",
        "name": "API REST / GraphQL",
        "description": "OWASP API Security Top 10: BOLA, autenticación rota, exposición de datos.",
        "scan_mode": "standard",
        "instruction": (
            "Evalúa la API de {target} según el OWASP API Security Top 10 (2023). Descubre los "
            "endpoints (documentación, JS del cliente, rutas comunes), y prueba BOLA, "
            "autenticación rota, exposición excesiva de datos, mass assignment, falta de rate "
            "limiting y SSRF. Si hay GraphQL, prueba introspección y autorización por campo."
        ),
    },
    {
        "id": "code",
        "name": "Revisión de código",
        "description": "White-box sobre un repositorio (URL git o ruta local del pod).",
        "scan_mode": "standard",
        "instruction": (
            "Haz una revisión de seguridad white-box del código en {target}. Prioriza flujos de "
            "datos desde entradas de usuario hasta sinks peligrosos (SQL, comandos, ficheros, "
            "deserialización, plantillas) y fallos de autorización. Reporta solo hallazgos con "
            "ubicación en el código y una explicación de explotabilidad."
        ),
    },
]

SCAN_MODE_INFO: list[dict[str, str]] = [
    {
        "id": "quick",
        "name": "Rápido",
        "description": "Minutos. Ideal para pruebas dirigidas y retests.",
    },
    {
        "id": "standard",
        "name": "Estándar",
        "description": "Cobertura equilibrada. El punto de partida habitual.",
    },
    {
        "id": "deep",
        "name": "Profundo",
        "description": "Horas. Máxima cobertura, más agentes y más coste.",
    },
]
