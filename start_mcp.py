import sys
import os

# Garante codificação UTF-8 e silencia logs e banners do FastMCP para stdio limpo
os.environ["PYTHONIOENCODING"] = "utf-8"
os.environ["FASTMCP_SHOW_SERVER_BANNER"] = "false"
os.environ["FASTMCP_LOG_LEVEL"] = "CRITICAL"

project_root = os.path.dirname(os.path.abspath(__file__))
if project_root not in sys.path:
    sys.path.insert(0, project_root)

# Redireciona stderr para devnull para garantir comunicação JSON-RPC 100% perfeita com a Antigravity IDE
sys.stderr = open(os.devnull, 'w', encoding='utf-8')

from src.main import run

if __name__ == "__main__":
    run()
