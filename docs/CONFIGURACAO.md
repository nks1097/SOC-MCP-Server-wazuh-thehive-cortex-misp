# 📝 Guia Completo de Variáveis de Ambiente (`.env`)

Tabela descritiva de todas as variáveis de ambiente suportadas pelo **SOC MCP Server**:

| Variável | Padrão | Descrição |
| :--- | :--- | :--- |
| `WAZUH_HOST` | `127.0.0.1` | Endereço IP ou hostname do servidor Wazuh Manager |
| `WAZUH_API_PORT` | `55000` | Porta da API REST do Wazuh Manager |
| `WAZUH_USER` | `wazuh` | Usuário administrador da API do Wazuh |
| `WAZUH_PASS` | `wazuh` | Senha da API do Wazuh |
| `WAZUH_INDEXER_HOST` | `127.0.0.1` | Endereço IP do Wazuh Indexer (OpenSearch) |
| `WAZUH_INDEXER_PORT` | `9200` | Porta do Wazuh Indexer (OpenSearch) |
| `WAZUH_INDEXER_USER` | `admin` | Usuário do Wazuh Indexer |
| `WAZUH_INDEXER_PASS` | `admin` | Senha do Wazuh Indexer |
| `WAZUH_INDEXER_VERIFY_SSL` | `false` | Ignorar erros de certificado SSL autoassinado |
| `THEHIVE_URL` | `http://127.0.0.1:9000` | URL do servidor TheHive |
| `THEHIVE_API_KEY` | `""` | Chave de API do TheHive |
| `CORTEX_URL` | `http://127.0.0.1:9001` | URL do servidor Cortex |
| `CORTEX_API_KEY` | `""` | Chave de API do Cortex |
| `MISP_URL` | `https://127.0.0.1` | URL do servidor MISP |
| `MISP_API_KEY` | `""` | Chave de API do MISP |
| `FAST_MCP_NAME` | `SOC-MCP-Server` | Nome exibido do servidor MCP |
| `FAST_MCP_PORT` | `3000` | Porta de execução do FastMCP |