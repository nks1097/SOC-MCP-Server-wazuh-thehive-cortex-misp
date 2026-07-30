# 🛡️ SOC AI Orchestration - SOC MCP Server

[![Python 3.11+](https://img.shields.io/badge/Python-3.11+-blue.svg)](https://www.python.org/)
[![MCP](https://img.shields.io/badge/MCP-2025--11--25-green.svg)](https://modelcontextprotocol.io/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

**SOC MCP Server** é um Centro de Operações de Segurança (SOC) avançado e totalmente automatizado projetado como um servidor **MCP (Model Context Protocol)**. Construído com Python 3.11+ e FastMCP, ele se integra nativamente com **Wazuh SIEM**, **TheHive**, **Cortex**, **MISP** e **Docker/SSH** para fornecer capacidades completas de resposta a incidentes (SOAR) e triagem de segurança via Inteligência Artificial.

---

## 🚀 Arquitetura e Recursos

Este Servidor MCP permite que qualquer assistente de IA compatível (Antigravity IDE, LM Studio, Claude Desktop, ChatGPT Codex, VS Code) atue como um **Analista de SOC L1/L2 Autônomo**.

### 🔗 Integrações Nativas
- **Wazuh SIEM**: Busca de alertas, monitoramento de agentes, verificação de portas/processos e Resposta Ativa (bloqueio de IP, isolamento de host, quarentena).
- **TheHive**: Criação automatizada de casos de incidentes, gestão de observáveis e tarefas de triagem.
- **Cortex**: Disparo de analisadores de ameaças (VirusTotal, ANY.RUN, etc.) e extração de relatórios de inteligência.
- **MISP**: Consulta de IOCs (IPs, hashes, domínios) em feeds de inteligência de ameaças e publicação de eventos.
- **Docker & SSH**: Execução segura de comandos em containers e servidores para coleta de evidências e resposta ativa.

---

## 🔄 Playbook Automatizado de Triagem SOAR (`run_soc_playbook`)

Através do playbook orquestrado, o servidor executa automaticamente:
1. **Ingestão**: Recebe e analisa o alerta de segurança do Wazuh.
2. **Extração**: Extrai automaticamente IPs, hashes MD5/SHA256, URLs e domínios (IOCs).
3. **Enriquecimento**: Consulta a base de ameaças do MISP e executa analisadores do Cortex nos IOCs extraídos.
4. **Cálculo de Risco**: Calcula o Score de Risco geral (0 a 100) com base na severidade e correlação.
5. **Abertura de Chamado**: Cria automaticamente um Caso de alta prioridade no TheHive se o risco ultrapassar o limite.
6. **Relatórios Automáticos**: Gera relatórios técnicos e executivos em Markdown dinamicamente.

---

## 🛠️ Guia de Início Rápido

### Pré-requisitos
- **Python 3.11+**
- Credenciais e APIs do **Wazuh**, **TheHive**, **Cortex** e **MISP**

### Instalação e Configuração

1. **Clonar o repositório e entrar na pasta**:
   ```bash
   git clone https://github.com/nks1097/SOC-MCP-Server.git
   cd SOC-MCP-Server
   ```

2. **Configurar as Variáveis de Ambiente no `.env`**:
   Copie o modelo e edite com suas credenciais:
   ```bash
   cp .env.example .env
   ```

3. **Executar o Servidor MCP**:
   ```bash
   python start_mcp.py
   ```

4. **Integrar na sua IDE ou Cliente MCP**:

   #### 🔹 Para Antigravity IDE (`C:\Users\<SeuUsuario>\.gemini\config\mcp_config.json`):
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

   #### 🔹 Para LM Studio / Claude Desktop:
   ```json
   {
     "mcpServers": {
       "wazuh": {
         "command": "C:\\Caminho\\Para\\Seu\\python.exe",
         "args": [
           "C:\\Caminho\\Para\\Wazuh-MCP-Server\\start_mcp.py"
         ]
       }
     }
   }
   ```

---

## 📂 Estrutura do Projeto

```text
Wazuh-MCP-Server/
├── src/
│   ├── config/          # Configurações Pydantic e variáveis de ambiente
│   ├── core/            # Clientes assíncronos HTTP e SSH base
│   ├── models/          # Modelos de dados Pydantic (Alertas, IOCs, Casos)
│   ├── integrations/    # Módulos de integração (Wazuh, TheHive, Cortex, MISP, Docker)
│   ├── reports/         # Geradores de relatórios Markdown
│   ├── tools/           # Ferramentas expostas ao protocolo MCP
│   ├── workflows/       # Lógica do Playbook SOAR de resposta a incidentes
│   └── main.py          # Ponto de entrada do FastMCP
├── start_mcp.py         # Script principal de inicialização
├── start_mcp.py  # Ponte stdio <-> HTTP para clientes MCP
├── Dockerfile           # Imagem Docker
├── docker-compose.yml   # Orquestração Docker Compose
└── tests/               # Suíte de testes unitários e de integração
```

---

## 📜 Licença

Distribuído sob a licença **MIT**. Veja o arquivo [LICENSE](LICENSE) para mais detalhes.
