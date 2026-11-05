"""Transport harness for establishing resilient connections to MCP servers."""

import asyncio
import shlex
import sys
from typing import Optional
from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client

from mcpscan.models import ServerManifest


class MCPConnectorError(Exception):
    """Raised when transport connection or capability negotiation fails."""
    pass


class MCPConnector:
    """Resilient connector for MCP servers with timeout protection and manifest extraction."""

    def __init__(self, timeout: float = 15.0):
        self.timeout = timeout

    async def connect_stdio(self, command_str: str) -> ServerManifest:
        """Connect to a server over standard I/O (stdio) and extract full attack surface."""
        # Split command into executable and arguments safely
        if sys.platform == "win32":
            # On Windows, preserve python / node executable paths
            parts = shlex.split(command_str, posix=False)
        else:
            parts = shlex.split(command_str, posix=True)

        if not parts:
            raise MCPConnectorError("Command cannot be empty.")

        executable = parts[0]
        args = parts[1:]

        server_params = StdioServerParameters(
            command=executable,
            args=args,
            env=None,
        )

        try:
            return await asyncio.wait_for(
                self._run_stdio_session(server_params),
                timeout=self.timeout,
            )
        except asyncio.TimeoutError:
            raise MCPConnectorError(f"Connection timed out after {self.timeout}s.")
        except Exception as e:
            if isinstance(e, MCPConnectorError):
                raise
            raise MCPConnectorError(f"Failed to connect to MCP server: {str(e)}") from e

    async def _run_stdio_session(self, server_params: StdioServerParameters) -> ServerManifest:
        """Internal worker executing handshake and enumeration inside stdio context."""
        async with stdio_client(server_params) as (read_stream, write_stream):
            async with ClientSession(read_stream, write_stream) as session:
                init_result = await session.initialize()

                # Support both MCP v1 (camelCase) and v2 (snake_case)
                server_info_obj = getattr(init_result, "server_info", None) or getattr(init_result, "serverInfo", None)
                server_info = {
                    "name": getattr(server_info_obj, "name", "unknown") if server_info_obj else "unknown",
                    "version": getattr(server_info_obj, "version", "unknown") if server_info_obj else "unknown",
                }
                
                capabilities = getattr(init_result, "capabilities", None)
                cap_dict = capabilities.model_dump() if hasattr(capabilities, "model_dump") else {}

                # 1. Enumerate Tools
                tools_list = []
                try:
                    tools_result = await session.list_tools()
                    for tool in tools_result.tools:
                        input_schema = getattr(tool, "input_schema", None) or getattr(tool, "inputSchema", {})
                        if hasattr(input_schema, "model_dump"):
                            input_schema = input_schema.model_dump()
                        elif not isinstance(input_schema, dict):
                            input_schema = dict(input_schema) if input_schema else {}

                        tools_list.append({
                            "name": tool.name,
                            "description": tool.description or "",
                            "inputSchema": input_schema,
                        })
                except Exception:
                    pass

                # 2. Enumerate Resources
                resources_list = []
                try:
                    res_result = await session.list_resources()
                    for res in res_result.resources:
                        resources_list.append({
                            "uri": str(res.uri),
                            "name": res.name or "",
                            "description": res.description or "",
                            "mimeType": getattr(res, "mimeType", None),
                        })
                except Exception:
                    pass

                # 3. Enumerate Prompts
                prompts_list = []
                try:
                    prompts_result = await session.list_prompts()
                    for p in prompts_result.prompts:
                        prompts_list.append({
                            "name": p.name,
                            "description": p.description or "",
                            "arguments": [
                                {
                                    "name": a.name,
                                    "description": a.description or "",
                                    "required": getattr(a, "required", False),
                                }
                                for a in getattr(p, "arguments", []) or []
                            ],
                        })
                except Exception:
                    pass

                return ServerManifest(
                    server_info=server_info,
                    capabilities=cap_dict,
                    tools=tools_list,
                    resources=resources_list,
                    prompts=prompts_list,
                )
