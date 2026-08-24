from mcp.server.fastmcp import FastMCP


server = FastMCP("echo")


@server.tool()
def echo(value: str) -> str:
    return value


if __name__ == "__main__":
    server.run(transport="stdio")
