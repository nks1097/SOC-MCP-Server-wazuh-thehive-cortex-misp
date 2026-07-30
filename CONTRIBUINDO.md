# 🤝 Como Contribuir para o SOC MCP Server

Seja bem-vindo ao projeto **SOC MCP Server**! Este guia explica a estrutura do repositório, o fluxo de desenvolvimento e os padrões de código.

---

## 📋 Sumário

1. [Visão Geral do Repositório](#-visão-geral-do-repositório)
2. [Estratégia de Branches](#-estratégia-de-branches)
3. [Configuração do Ambiente de Desenvolvimento](#-configuração-do-ambiente-de-desenvolvimento)
4. [Estrutura do Projeto](#-estrutura-do-projeto)
5. [Padrões de Código](#-padrões-de-código)

---

## 🏗️ Visão Geral do Repositório

Este repositório fornece uma implementação de produção do protocolo **MCP (Model Context Protocol)** para integração direta com ferramentas de segurança SOC:

- Integração nativa com **Wazuh SIEM**, **TheHive**, **Cortex**, **MISP** e **Docker/SSH**.
- Playbook automatizado de triagem SOAR (`run_soc_playbook`).

---

## 🌳 Estratégia de Branches

### Branch Principal
- **`main`**: Código estável e pronto para produção.

---

## 🛠️ Configuração do Ambiente de Desenvolvimento

### Pré-requisitos
- **Python 3.11+**
- **Git**
- Credenciais ativas para Wazuh, TheHive, Cortex e MISP

### Configuração Inicial

1. **Clonar o repositório**:
   ```bash
   git clone https://github.com/nks1097/SOC-MCP-Server.git
   cd SOC-MCP-Server
   ```

2. **Criar e ativar o ambiente virtual (venv)**:
   ```bash
   python -m venv .venv
   # No Windows (PowerShell):
   .\.venv\Scripts\Activate.ps1
   ```

3. **Instalar dependências de desenvolvimento**:
   ```bash
   pip install -r requirements.txt
   ```

4. **Configurar o arquivo `.env`**:
   Copie o modelo de ambiente e ajuste com os dados do seu ambiente:
   ```bash
   cp .env.example .env
   ```

---

## 📐 Padrões de Código

- **PEP 8**: Siga as diretrizes padrão de estilo do Python.
- **Formatação de Docstrings**: Forneça descrições claras em Português para todas as ferramentas expostas ao protocolo MCP.
- **Segurança**: Nunca inclua senhas, chaves de API ou tokens nos arquivos commitados.