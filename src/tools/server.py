from fastmcp import FastMCP
from src.config.settings import settings

# Instância única do servidor FastMCP sem importações circulares
mcp = FastMCP(settings.FAST_MCP_NAME)
