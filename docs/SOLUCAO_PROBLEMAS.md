# 🛠️ Guia de Solução de Problemas (Troubleshooting)

Este guia apresenta soluções para os problemas mais comuns ao configurar e executar o Servidor SOC MCP.

---

## 🔌 Problemas de Conexão com o Servidor MCP

### Testando o Endpoint da Ponte MCP e FastMCP

```bash
# Testar a saúde do servidor MCP local
curl -I http://localhost:3000/
# Resultado esperado: HTTP/1.1 200 OK

# Testar a inicialização direta do FastMCP em Python
python start_mcp.py
```

---

## 💻 Problemas de Conexão com a IDE e Clientes MCP

### Antigravity IDE / LM Studio / Claude Desktop

```json
{
  "mcpServers": {
    "wazuh": {
      "command": "C:\\Python311\\python.exe",
      "args": [
        "C:\\Caminho\\Para\\Wazuh-MCP-Server\\start_mcp.py"
      ]
    }
  }
}
```

**Causas Comuns de Erros:**
- O caminho do executável do `python.exe` está incorreto no arquivo de configuração.
- O caminho do script `wazuh-mcp-bridge.py` está incorreto.
- Faltam dependências no ambiente virtual (execute `pip install -r requirements.txt`).

---

## 🔑 Erros de Autenticação nas APIs

### Autenticação da API do Wazuh Manager (Porta 55000)

```bash
# Testar credenciais do Wazuh diretamente
curl -k -u "wazuh:SuaSenha" "https://192.168.0.248:55000/security/user/authenticate"
```

### Autenticação do Wazuh Indexer / OpenSearch (Porta 9200)

```bash
# Testar acesso ao Indexer
curl -k -u "admin:SuaSenhaIndexer" "https://192.168.0.248:9200/_cluster/health"
```

**Verificações Importantes:**
- Verifique se a variável `WAZUH_INDEXER_VERIFY_SSL=false` está definida no seu `.env` se estiver utilizando certificados autoassinados.
- Verifique se a diretiva `network.host: 0.0.0.0` está configurada no `/etc/wazuh-indexer/opensearch.yml` no servidor Linux.
