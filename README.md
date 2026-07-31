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




## 🛠️ Catálogo de Ferramentas MCP (70 Tools Disponíveis)

O **SOC MCP Server** disponibiliza 70 ferramentas organizadas em tabelas por módulo funcional para automação SOAR, resposta a incidentes e inteligência de ameaças:

### 🛡️ 1. Telemetria, SIEM & EDR (Wazuh)

| Nº | Ferramenta MCP | Módulo | Descrição Operacional |
| :---: | :--- | :---: | :--- |
| **01** | obter_alertas_wazuh | Wazuh SIEM | Consulta alertas e eventos de segurança com filtros avançados. |
| **02** | obter_resumo_alertas_wazuh | Wazuh SIEM | Agregação estatística de alertas por severidade e nível. |
| **03** | obter_agentes_wazuh | Wazuh EDR | Lista todos os agentes registrados na infraestrutura. |
| **04** | obter_agentes_ativos_wazuh | Wazuh EDR | Filtra apenas os agentes online e ativos no cluster. |
| **05** | erificar_saude_agente | Wazuh EDR | Diagnóstico de conectividade, versão e status do agente. |
| **06** | obter_inventario_sistema_agente | Wazuh Syscollector | Coleta hardware, sistema operacional, portas e pacotes. |
| **07** | obter_processos_agente | Wazuh Syscollector | Enumeração em tempo real dos processos ativos no host. |
| **08** | obter_portas_agente | Wazuh Syscollector | Lista portas de rede abertas e serviços em escuta. |
| **09** | obter_configuracao_agente | Wazuh Agent | Exibe as configurações ativas e módulos do agente. |
| **10** | obter_vulnerabilidades_wazuh | Wazuh Vulnerability | Retorna relatórios de CVEs detectadas nos ativos. |
| **11** | obter_vulnerabilidades_criticas_wazuh | Wazuh Vulnerability | Filtra apenas vulnerabilidades com severidade Crítica/Alta. |
| **12** | obter_detalhes_vulnerabilidade_wazuh | Wazuh Vulnerability | Métricas CVSS, descrição e orientações de correção da CVE. |
| **13** | obter_dados_cti_cve_wazuh | Wazuh CTI | Consulta inteligência de ameaças associada a uma CVE. |
| **14** | obter_regras_wazuh | Wazuh Rules | Consulta o catálogo completo de regras de detecção. |
| **15** | obter_detalhes_regra_wazuh | Wazuh Rules | Exibe a definição XML, grupo e severidade de uma regra. |
| **16** | uscar_eventos_fim | Wazuh FIM | Monitoramento de Integridade de Arquivos (Syscheck). |
| **17** | uscar_eventos_seguranca | Wazuh Audit | Busca em logs de auditoria e segurança por termo. |
| **18** | obter_saude_cluster_wazuh | Wazuh Cluster | Monitora a saúde, carga e nós do cluster do Manager. |
| **19** | obter_informacoes_gerenciador_wazuh | Wazuh Manager | Estatísticas e versão do gerenciador Wazuh. |
| **20** | uscar_logs_gerenciador_wazuh | Wazuh Logs | Consulta logs operacionais internos do Manager. |
| **21** | obter_logs_erro_gerenciador_wazuh | Wazuh Logs | Filtra erros críticos no gerenciador Wazuh. |
| **22** | nalisar_padroes_alertas | Wazuh Analytics | Identificação de picos e anomalias de ataques no tempo. |
| **23** | nalisar_ameaca_seguranca | Wazuh Analytics | Análise heurística de eventos de ameaça. |
| **24** | obter_principais_ameacas_seguranca | Wazuh Analytics | Ranking das maiores ameaças detectadas na rede. |
| **25** | alidar_conexao_wazuh | System Check | Valida a autenticação e conectividade da API REST. |

---

### ⚡ 2. Resposta Ativa & Contenção Forense (Active Response)

| Nº | Ferramenta MCP | Ação SOAR | Descrição Operacional |
| :---: | :--- | :---: | :--- |
| **26** | isolar_host_wazuh | Contenção | Bloqueio total de rede do ativo comprometido. |
| **27** | desisolar_host_wazuh | Restauração | Restauração da conectividade de rede do host. |
| **28** | loquear_ip_wazuh | Firewall | Bloqueio de IP atacante no firewall do agente. |
| **29** | permitir_firewall_wazuh | Firewall | Liberação de regras de IP no firewall. |
| **30** | loquear_firewall_wazuh | Firewall | Aplicação de regra customizada de firewall. |
| **31** | encerrar_processo_wazuh | Process Kill | Encerramento imediato de processo malicioso (PID/Nome). |
| **32** | quarentena_arquivo_wazuh | Quarentena | Mover arquivos maliciosos para a quarentena isolada. |
| **33** | 
estaurar_arquivo_wazuh | Quarentena | Restauração de arquivo da quarentena ao disco. |
| **34** | desabilitar_usuario_wazuh | Identity | Desativação imediata de conta de usuário comprometida. |
| **35** | habilitar_usuario_wazuh | Identity | Reativação de conta de usuário. |
| **36** | 
einiciar_servico_wazuh | Service | Reinicialização de serviços ou do agente Wazuh. |
| **37** | 
esposta_ativa_wazuh | Script Exec | Disparo de scripts customizados de Active Response. |
| **38** | executar_comando_resposta_ativa_wazuh | Command Exec | Execução controlada de comandos de resposta. |
| **39** | executar_avaliacao_risco | Risk Analysis | Cálculo de Risk Score dinâmico do ativo (0-100). |
| **40** | executar_teste_conformidade | Compliance | Auditoria contra padrões CIS / PCI-DSS / HIPAA. |

---

### 🐝 3. TheHive 5, Cortex, MISP & Threat Hunting

| Nº | Ferramenta MCP | Integração | Descrição Operacional |
| :---: | :--- | :---: | :--- |
| **41** | criar_caso_thehive | TheHive 5 | Abertura automatizada de casos de incidentes. |
| **42** | listar_casos_thehive | TheHive 5 | Consulta da fila de casos abertos e encerrados. |
| **43** | obter_caso_thehive | TheHive 5 | Detalhes de severidade, histórico e status de um caso. |
| **44** | tualizar_caso_thehive | TheHive 5 | Alteração de status (Open, Resolved), tags ou TLP. |
| **45** | dicionar_observavel_thehive | TheHive 5 | Registro de IOCs (Hash, IP, URL, Domínio) no caso. |
| **46** | obter_observaveis_thehive | TheHive 5 | Enumeração de todos os IOCs vinculados a um caso. |
| **47** | listar_analisadores_cortex | Cortex | Exibe analisadores disponíveis (VirusTotal, Shodan). |
| **48** | executar_analise_cortex | Cortex | Submete IOCs para análise automatizada no Cortex. |
| **49** | uscar_misp | MISP CTI | Pesquisa de indicadores de comprometimento no MISP. |
| **50** | publicar_evento_misp | MISP CTI | Exportação e compartilhamento de eventos no MISP. |
| **51** | erificar_reputacao_ioc | CTI Global | Consulta global de reputação de IOCs. |
| **52** | investigar_alerta_wazuh | SOAR Flow | Correlação entre Wazuh + TheHive + Cortex + MISP. |
| **53** | 
esponder_incidente_soc | SOAR Flow | Fluxo de contenção e gestão de incidente em 1-clique. |
| **54** | cacada_ameacas_threat_hunting | Threat Hunting | Varredura pró-ativa de TTPs da matriz MITRE. |
| **55** | investigar_ip | Forensic | Investigação aprofundada de reputação e tráfego de IPs. |
| **56** | investigar_hash | Forensic | Consulta forense de reputação de hashes (SHA256/MD5). |
| **57** | investigar_dominio | Forensic | Análise DNS, WHOIS e reputação de domínios. |
| **58** | investigar_host | Forensic | Diagnóstico completo de integridade e risco de um host. |
| **59** | 	riagem_alerta | AI Triage | Triagem automática com veredito (TP/FP). |
| **60** | explicar_mitre | ATT&CK | Mapeamento de táticas e técnicas MITRE ATT&CK. |
| **61** | cacada_ip | Threat Hunting | Busca de rastros de um IP em toda a telemetria. |
| **62** | cacada_hash | Threat Hunting | Caça pró-ativa por hashes maliciosos nos agentes. |
| **63** | gerar_relatorios_incidente | Reporting | Geração de relatórios forenses em Markdown/PDF. |
| **64** | gerar_relatorio_seguranca | Reporting | Relatório de postura de segurança e conformidade. |

---

### 🐳 4. Gestão de Infraestrutura Docker & SSH

| Nº | Ferramenta MCP | Categoria | Descrição Operacional |
| :---: | :--- | :---: | :--- |
| **65** | docker_ps | Docker | Monitoramento dos contêineres ativos da pilha SOC. |
| **66** | docker_logs | Docker | Coleta de logs operacionais em tempo real dos serviços. |
| **67** | docker_restart | Docker | Reinício controlado dos serviços SOC (Wazuh, TheHive, MISP). |
| **68** | ssh_execute | Administration | Execução de comandos administrativos autorizados via SSH. |
