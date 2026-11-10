"""Transport harness for establishing resilient connections to MCP servers."""

import asyncio
import shlex
import sys
from typing import Any, Dict, List

from mcp import ClientSession, StdioServerParameters
from mcp.client.sse import sse_client
from mcp.client.stdio import stdio_client

from mcpscan.models import ServerManifest


class MCPConnectorError(Exception):
    """Raised when transport connection or capability negotiation fails."""


class MCPConnector:
    """Connector for MCP servers with timeout protection and honest scan status."""

    def __init__(self, timeout: float = 15.0):
        if timeout <= 0:
            raise ValueError("timeout must be greater than zero")
        self.timeout = timeout

    async def connect_stdio(self, command_str: str) -> ServerManifest:
        """Connect over stdio and extract the server's declared attack surface."""
        parts = shlex.split(command_str, posix=sys.platform != "win32")
        if not parts:
            raise MCPConnectorError("Command cannot be empty.")

        params = StdioServerParameters(command=parts[0], args=parts[1:], env=None)
        try:
            return await asyncio.wait_for(self._run_stdio_session(params), timeout=self.timeout)
        except asyncio.TimeoutError as exc:
            raise MCPConnectorError(f"Connection timed out after {self.timeout}s.") from exc
        except Exception as exc:
            if isinstance(exc, MCPConnectorError):
                raise
            # Avoid echoing target-controlled exception text into logs/reports.
            raise MCPConnectorError(f"Failed to connect to MCP server ({type(exc).__name__}).") from exc

    async def connect_sse(self, sse_url: str) -> ServerManifest:
        """Connect over HTTP/SSE and extract the server's declared attack surface."""
        if not sse_url or not sse_url.startswith(("http://", "https://")):
            raise MCPConnectorError("Invalid SSE URL. Must begin with http:// or https://")
        try:
            return await asyncio.wait_for(self._run_sse_session(sse_url), timeout=self.timeout)
        except asyncio.TimeoutError as exc:
            raise MCPConnectorError(f"SSE connection timed out after {self.timeout}s.") from exc
        except Exception as exc:
            if isinstance(exc, MCPConnectorError):
                raise
            raise MCPConnectorError(f"Failed to connect to MCP SSE server ({type(exc).__name__}).") from exc

    async def _run_sse_session(self, sse_url: str) -> ServerManifest:
        async with sse_client(sse_url) as (read_stream, write_stream):
            async with ClientSession(read_stream, write_stream) as session:
                return await self._extract_manifest_from_session(session)

    async def _run_stdio_session(self, params: StdioServerParameters) -> ServerManifest:
        async with stdio_client(params) as (read_stream, write_stream):
            async with ClientSession(read_stream, write_stream) as session:
                return await self._extract_manifest_from_session(session)

    async def _extract_manifest_from_session(self, session: ClientSession) -> ServerManifest:
        """Initialize and enumerate advertised surfaces; record failures explicitly."""
        initialized = await session.initialize()
        server_info_obj = getattr(initialized, "server_info", None) or getattr(initialized, "serverInfo", None)
        server_info = {
            "name": getattr(server_info_obj, "name", "unknown") if server_info_obj else "unknown",
            "version": getattr(server_info_obj, "version", "unknown") if server_info_obj else "unknown",
        }
        capabilities = getattr(initialized, "capabilities", None)
        if hasattr(capabilities, "model_dump"):
            cap_dict: Dict[str, Any] = capabilities.model_dump()
        elif isinstance(capabilities, dict):
            cap_dict = capabilities
        else:
            cap_dict = {}

        has_tools = bool(cap_dict.get("tools") is not None or getattr(capabilities, "tools", None) is not None)
        has_resources = bool(cap_dict.get("resources") is not None or getattr(capabilities, "resources", None) is not None)
        has_prompts = bool(cap_dict.get("prompts") is not None or getattr(capabilities, "prompts", None) is not None)

        errors: List[str] = []

        tools = []
        if has_tools:
            try:
                result = await session.list_tools()
                for tool in result.tools:
                    schema = getattr(tool, "input_schema", None) or getattr(tool, "inputSchema", {})
                    if hasattr(schema, "model_dump"):
                        schema = schema.model_dump()
                    elif not isinstance(schema, dict):
                        schema = dict(schema) if schema else {}
                    tools.append({"name": tool.name, "description": tool.description or "", "inputSchema": schema})
            except Exception as exc:
                errors.append(f"tools enumeration failed ({type(exc).__name__})")

        resources = []
        if has_resources:
            try:
                result = await session.list_resources()
                for resource in result.resources:
                    resources.append({
                        "uri": str(resource.uri),
                        "name": resource.name or "",
                        "description": resource.description or "",
                        "mimeType": getattr(resource, "mimeType", None),
                    })
            except Exception as exc:
                errors.append(f"resources enumeration failed ({type(exc).__name__})")

        prompts = []
        if has_prompts:
            try:
                result = await session.list_prompts()
                for prompt in result.prompts:
                    prompts.append({
                        "name": prompt.name,
                        "description": prompt.description or "",
                        "arguments": [
                            {"name": arg.name, "description": arg.description or "", "required": getattr(arg, "required", False)}
                            for arg in getattr(prompt, "arguments", []) or []
                        ],
                    })
            except Exception as exc:
                errors.append(f"prompts enumeration failed ({type(exc).__name__})")

        return ServerManifest(
            server_info=server_info,
            capabilities=cap_dict,
            tools=tools,
            resources=resources,
            prompts=prompts,
            scan_complete=not errors,
            scan_errors=errors,
        )
