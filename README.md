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


## 🛠️ Catálogo Completo das Ferramentas MCP (60+ Tools Disponíveis)

O **SOC MCP Server** disponibiliza um ecossistema completo de ferramentas categorizadas para automação SOAR, resposta a incidentes e inteligência de ameaças:

### 🛡️ 1. Wazuh EDR / SIEM (Telemetria, Vulnerabilidades e Monitoramento)
- obter_alertas_wazuh: Consulta alertas e eventos de segurança no Wazuh.
- obter_resumo_alertas_wazuh: Obtém estatísticas e agregação de alertas por severidade.
- obter_agentes_wazuh: Lista todos os agentes registrados na infraestrutura.
- obter_agentes_ativos_wazuh: Retorna apenas os agentes online no cluster.
- erificar_saude_agente: Checa status, conectividade e versão do agente.
- obter_inventario_sistema_agente: Coleta hardware, SO, portas e pacotes do agente.
- obter_processos_agente: Enumera os processos em execução no host cliente.
- obter_portas_agente: Lista portas de rede abertas e escutando no agente.
- obter_configuracao_agente: Consulta as configurações ativas do agente Wazuh.
- obter_vulnerabilidades_wazuh: Retorna vulnerabilidades detectadas (CVEs).
- obter_vulnerabilidades_criticas_wazuh: Filtra apenas vulnerabilidades Críticas/Altas.
- obter_detalhes_vulnerabilidade_wazuh: Detalha métricas CVSS e correções de uma CVE.
- obter_dados_cti_cve_wazuh: Consulta inteligência de ameaças sobre uma CVE.
- obter_regras_wazuh: Consulta o catálogo de regras de detecção.
- obter_detalhes_regra_wazuh: Exibe a definição XML e severidade de uma regra.
- uscar_eventos_fim: Busca eventos de integridade de arquivos (FIM/Syscheck).
- uscar_eventos_seguranca: Filtra logs de auditoria e segurança por termo.
- obter_saude_cluster_wazuh: Monitora a saúde e nós do cluster do Manager.
- obter_informacoes_gerenciador_wazuh: Retorna versão e estatísticas do Manager.
- uscar_logs_gerenciador_wazuh: Consulta os logs internos do gerenciador Wazuh.
- obter_logs_erro_gerenciador_wazuh: Filtra erros e alertas críticos do gerenciador.
- nalisar_padroes_alertas: Identifica anomalias e picos de alertas.
- nalisar_ameaca_seguranca: Executa análise heurística de eventos de ameaça.
- obter_principais_ameacas_seguranca: Lista os top vetores de ataque detectados.
- alidar_conexao_wazuh: Valida a conectividade da API REST e credenciais.

### ⚡ 2. Resposta Ativa & Contenção no Wazuh (Active Response)
- isolar_host_wazuh: Executa o isolamento de rede do agente afetado.
- desisolar_host_wazuh: Restaura a conectividade de rede do host.
- loquear_ip_wazuh: Bloqueia um IP malicioso no firewall do host alvo.
- permitir_firewall_wazuh: Remove o bloqueio de um IP no firewall.
- loquear_firewall_wazuh: Aplica regra customizada de bloqueio de porta/IP.
- encerrar_processo_wazuh: Termina a execução de um processo suspeito (PID/Nome).
- quarentena_arquivo_wazuh: Move um arquivo malicioso para a quarentena isolada.
- 
estaurar_arquivo_wazuh: Restaura um arquivo da quarentena de volta ao disco.
- desabilitar_usuario_wazuh: Desabilita uma conta de usuário comprometida.
- habilitar_usuario_wazuh: Reabilita uma conta de usuário.
- 
einiciar_servico_wazuh: Reinicia um serviço do sistema ou o próprio agente.
- 
esposta_ativa_wazuh: Dispara scripts customizados de Active Response.
- executar_comando_resposta_ativa_wazuh: Executa comandos arbitrários autorizados.
- executar_avaliacao_risco: Calcula o Risk Score dinâmico do ativo.
- executar_teste_conformidade: Valida conformidade contra benchmarks CIS / PCI-DSS.

### 🐝 3. TheHive 5 (Gestão de Casos e Incidentes)
- criar_caso_thehive: Abre um novo caso de incidente no TheHive.
- listar_casos_thehive: Consulta a lista de casos abertos e encerrados.
- obter_caso_thehive: Detalha a severidade, descrição e status de um caso.
- tualizar_caso_thehive: Altera status (Open, Resolved), severidade ou tags.
- dicionar_observavel_thehive: Registra IOCs (IP, Hash, URL, Domínio) no caso.
- obter_observaveis_thehive: Lista todos os observáveis associados ao caso.

### 🔬 4. Cortex (Análise Automatizada de Observáveis)
- listar_analisadores_cortex: Lista analisadores ativos (VirusTotal, Shodan, AbuseIPDB).
- executar_analise_cortex: Dispara análise automatizada sobre um IOC.

### 🌐 5. MISP (Threat Intelligence Sharing)
- uscar_misp: Pesquisa eventos de ameaças e IOCs na base do MISP.
- publicar_evento_misp: Exporta e compartilha novos IOCs no barramento do MISP.
- erificar_reputacao_ioc: Consulta a reputação global de um IOC nas bases CTI.

### 🎯 6. Orquestração SOC & Threat Hunting Integrado
- investigar_alerta_wazuh: Correlação completa entre Wazuh + TheHive + Cortex + MISP.
- 
esponder_incidente_soc: Orquestração de resposta em 1-clique (Contenção + Caso).
- cacada_ameacas_threat_hunting: Executa varreduras pró-ativas de TTPs MITRE.
- investigar_ip: Análise aprofundada de reputação e tráfego de um IP.
- investigar_hash: Consulta de reputação de hashes de arquivos (SHA256/MD5).
- investigar_dominio: Análise DNS, WHOIS e reputação de domínios.
- investigar_host: Diagnóstico completo de segurança de um endpoint.
- 	riagem_alerta: Triagem automática de alertas com veredito (TP/FP).
- explicar_mitre: Mapeia táticas e técnicas da matriz MITRE ATT&CK.
- cacada_ip: Busca rastros de um IP em toda a telemetria do ambiente.
- cacada_hash: Variação pró-ativa por hashes maliciosos nos agentes.
- gerar_relatorios_incidente: Gera relatórios forenses em Markdown/PDF.
- gerar_relatorio_seguranca: Emite relatórios de postura de segurança e conformidade.

### 🐳 7. Gestão de Infraestrutura Docker & SSH
- docker_ps: Lista contêineres ativos na infraestrutura SOC.
- docker_logs: Coleta logs de serviços Docker em tempo real.
- docker_restart: Reinicia serviços da pilha SOC (Wazuh/TheHive/Cortex/MISP).
- ssh_execute: Executa comandos de gestão remota autorizada via SSH.
