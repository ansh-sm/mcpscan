"""Quick standalone smoke test server for stdio connectivity using modern MCP 2.x API."""

from mcp.server.mcpserver import MCPServer

server = MCPServer("DemoServer")

@server.tool()
def calculate_sum(a: int, b: int) -> int:
    """Calculate the sum of two integers."""
    return a + b

if __name__ == "__main__":
    server.run(transport="stdio")
