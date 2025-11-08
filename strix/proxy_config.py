"""
Proxy configuration module for Strix.

This module handles upstream proxy configuration for both tool traffic and LLM traffic.
Supports both SOCKS5 and HTTP proxies as requested in:
https://github.com/usestrix/strix/issues/19
"""

import os
from dataclasses import dataclass
from typing import Any
from urllib.parse import urlparse


@dataclass
class ProxyConfig:
    """Configuration for upstream proxies."""

    tools_proxy: str | None = None
    llm_proxy: str | None = None
    all_proxy: str | None = None

    def __post_init__(self) -> None:
        """Validate proxy configurations."""
        for proxy_name, proxy_url in [
            ("STRIX_PROXY_TOOLS", self.tools_proxy),
            ("STRIX_PROXY_LLM", self.llm_proxy),
            ("STRIX_PROXY_ALL", self.all_proxy),
        ]:
            if proxy_url:
                self._validate_proxy_url(proxy_url, proxy_name)

    def _validate_proxy_url(self, proxy_url: str, env_var_name: str) -> None:
        """Validate proxy URL format."""
        try:
            parsed = urlparse(proxy_url)
            if parsed.scheme not in ["http", "https", "socks5", "socks5h"]:
                raise ValueError(
                    f"Invalid proxy scheme in {env_var_name}: {parsed.scheme}. "
                    "Supported schemes: http, https, socks5, socks5h"
                )
            if not parsed.hostname:
                raise ValueError(f"Missing hostname in {env_var_name}: {proxy_url}")
            if not parsed.port:
                raise ValueError(f"Missing port in {env_var_name}: {proxy_url}")
        except Exception as e:
            raise ValueError(f"Invalid proxy URL in {env_var_name}: {proxy_url}") from e

    def get_tools_proxy(self) -> str | None:
        """Get proxy configuration for tools traffic."""
        return self.tools_proxy or self.all_proxy

    def get_llm_proxy(self) -> str | None:
        """Get proxy configuration for LLM traffic."""
        return self.llm_proxy or self.all_proxy

    def get_requests_proxies(self, proxy_type: str = "tools") -> dict[str, str] | None:
        """
        Get proxy configuration in requests library format.

        Args:
            proxy_type: Either 'tools' or 'llm' to determine which proxy to use.

        Returns:
            Dictionary with 'http' and 'https' keys, or None if no proxy configured.
        """
        proxy_url = self.get_tools_proxy() if proxy_type == "tools" else self.get_llm_proxy()
        if not proxy_url:
            return None

        return {"http": proxy_url, "https": proxy_url}

    def get_httpx_proxies(self, proxy_type: str = "tools") -> dict[str, str] | None:
        """
        Get proxy configuration in httpx library format.

        Args:
            proxy_type: Either 'tools' or 'llm' to determine which proxy to use.

        Returns:
            Dictionary with protocol keys, or None if no proxy configured.
            
        Note:
            For SOCKS proxies with httpx, we need to use httpx-socks library
            and create AsyncProxyTransport instead of simple URL strings.
        """
        proxy_url = self.get_tools_proxy() if proxy_type == "tools" else self.get_llm_proxy()
        if not proxy_url:
            return None

        # For httpx, we can return the same format as requests for HTTP proxies
        # SOCKS proxies need special handling with httpx-socks
        parsed = urlparse(proxy_url)
        if parsed.scheme in ["socks5", "socks5h"]:
            # We'll handle SOCKS in the calling code using httpx-socks
            return {"_socks_proxy": proxy_url}
        else:
            # HTTP/HTTPS proxies work the same as requests
            return {"http://": proxy_url, "https://": proxy_url}

    def get_litellm_proxy_env(self) -> dict[str, str]:
        """
        Get environment variables for litellm proxy configuration.

        Returns:
            Dictionary of environment variables to set for litellm.
        """
        env_vars = {}
        llm_proxy = self.get_llm_proxy()

        if llm_proxy:
            # litellm supports standard proxy environment variables
            env_vars["HTTP_PROXY"] = llm_proxy
            env_vars["HTTPS_PROXY"] = llm_proxy

        return env_vars


def load_proxy_config() -> ProxyConfig:
    """Load proxy configuration from environment variables."""
    return ProxyConfig(
        tools_proxy=os.getenv("STRIX_PROXY_TOOLS"),
        llm_proxy=os.getenv("STRIX_PROXY_LLM"),
        all_proxy=os.getenv("STRIX_PROXY_ALL"),
    )


def configure_global_proxies() -> ProxyConfig:
    """
    Configure global proxy settings and return the configuration.

    This function should be called early in the application startup
    to ensure proxy settings are applied globally.
    """
    config = load_proxy_config()

    # Set environment variables for litellm if LLM proxy is configured
    llm_proxy_env = config.get_litellm_proxy_env()
    for key, value in llm_proxy_env.items():
        os.environ[key] = value

    return config


# Global proxy configuration instance
_global_proxy_config: ProxyConfig | None = None


def get_proxy_config() -> ProxyConfig:
    """Get the global proxy configuration instance."""
    global _global_proxy_config  # noqa: PLW0603
    if _global_proxy_config is None:
        _global_proxy_config = configure_global_proxies()
    return _global_proxy_config