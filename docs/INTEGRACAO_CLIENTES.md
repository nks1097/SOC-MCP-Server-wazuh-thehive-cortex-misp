# 🤖 Guia de Integração com Assistentes de IA e Clientes MCP

Este guia orienta como integrar o Servidor SOC MCP em qualquer assistente de Inteligência Artificial compatível com o protocolo MCP.

---

## ⚙️ Arquivo de Configuração Padrão (`mcp_config.json`)

Adicione o bloco abaixo no arquivo de configuração do seu cliente MCP:

```json
{
  "mcpServers": {
    "wazuh": {
      "command": "C:\\Caminho\\Para\\Seu\\python.exe",
      "args": [
        "C:\\Caminho\\Para\\Wazuh-MCP-Server\\start_mcp.py"
      ],
      "env": {
        "FASTMCP_LOG_LEVEL": "CRITICAL",
        "FASTMCP_SHOW_SERVER_BANNER": "false",
        "PYTHONIOENCODING": "utf-8"
      }
    }
  }
}
```

---

## 🛠️ Clientes Suportados

- **Antigravity IDE**: Adicione em `C:\Users\<SeuUsuario>\.gemini\config\mcp_config.json`.
- **LM Studio**: Adicione nas configurações de MCP Servers.
- **Claude Desktop**: Adicione em `%APPDATA%\Claude\claude_desktop_config.json`.
- **ChatGPT Codex**: Adicione em `C:\Users\<SeuUsuario>\.codex\config.toml`.
