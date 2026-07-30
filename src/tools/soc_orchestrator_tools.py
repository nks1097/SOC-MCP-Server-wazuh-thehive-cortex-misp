from typing import Dict, Any, List
import asyncio
import json

from src.tools.server import mcp
from src.tools.mcp_tools import get_wazuh, get_misp, get_cortex, get_thehive
try:
    from src.tools.wazuh_advanced_tools import get_advanced_wazuh
except ImportError:
    get_advanced_wazuh = None

@mcp.tool()
async def investigar_ip(ip: str) -> Dict[str, Any]:
    """
    Super-ferramenta SOC autônoma: Investiga um IP de ponta a ponta correlacionando Wazuh, MISP e Cortex.
    Retorna estatísticas de detecção, inteligência de ameaça, cálculo de risco e um relatório Markdown executivo.
    """
    wazuh = get_wazuh()
    misp = get_misp()
    
    # 1. Busca paralela em Wazuh e MISP
    wazuh_alerts_task = wazuh.search_alerts(ip, limit=10)
    misp_hits_task = misp.search_attributes(ip)
    
    wazuh_alerts, misp_hits = await asyncio.gather(wazuh_alerts_task, misp_hits_task, return_exceptions=True)
    
    if isinstance(wazuh_alerts, Exception):
        wazuh_alerts = []
    if isinstance(misp_hits, Exception):
        misp_hits = []
        
    # 2. Cálculo do Risk Score (0 a 100)
    wazuh_count = len(wazuh_alerts)
    misp_count = len(misp_hits)
    
    risk_score = min(100, (wazuh_count * 15) + (misp_count * 35))
    if risk_score == 0 and (wazuh_count > 0 or misp_count > 0):
        risk_score = 20
        
    status = "CRÍTICO - Ação Imediata Recomendada" if risk_score >= 70 else ("SUSPEITO - Requer Investigação" if risk_score >= 30 else "BAIXO RISCO / LIMPO")
    
    # 3. Montagem do Resumo Executivo em Markdown
    md = f"## 🛡️ Dossiê SOC de Investigação: IP `{ip}`\n\n"
    md += f"**Status de Risco:** {status}\n"
    md += f"**Risk Score Calculado:** `{risk_score}/100`\n\n"
    md += "### 📊 Resumo de Correlação\n"
    md += f"- **Avistamentos no Wazuh (SIEM):** {wazuh_count} alertas recentes encontrados.\n"
    md += f"- **Ocorrências no MISP (Threat Intel):** {misp_count} feeds/atributos associados.\n\n"
    
    if wazuh_count > 0:
        md += "### 🚨 Principais Alertas no Wazuh\n"
        for idx, alert in enumerate(wazuh_alerts[:3], 1):
            rule_id = alert.get("rule", {}).get("id", "N/A")
            desc = alert.get("rule", {}).get("description", "Sem descrição")
            level = alert.get("rule", {}).get("level", 0)
            md += f"{idx}. **[Regra {rule_id} - Nível {level}]**: {desc}\n"
        md += "\n"
        
    if misp_count > 0:
        md += "### 🌐 Inteligência no MISP\n"
        for idx, hit in enumerate(misp_hits[:3], 1):
            cat = hit.get("category", "N/A")
            type_str = hit.get("type", "N/A")
            event_id = hit.get("event_id", "N/A")
            md += f"{idx}. **[Evento {event_id}]** Categoria: `{cat}` | Tipo: `{type_str}`\n"
        md += "\n"
        
    md += "### ⚡ Recomendações de Ação SOC\n"
    if risk_score >= 70:
        md += f"- [ ] **Contenção Imediata:** Executar a ferramenta `respond_to_incident` ou Active Response `firewall-drop` para bloquear o IP `{ip}`.\n"
        md += f"- [ ] **Escalonamento:** Abrir caso de alta prioridade no TheHive via `create_case`.\n"
    elif risk_score >= 30:
        md += f"- [ ] **Monitoramento:** Adicionar o IP `{ip}` à lista de observação no SIEM.\n"
        md += f"- [ ] **Verificação de Endpoint:** Auditar os agentes Wazuh que comunicaram com este endereço.\n"
    else:
        md += "- [ ] Nenhuma ação de bloqueio imediata é necessária no momento.\n"
        
    return {
        "ip": ip,
        "risk_score": risk_score,
        "status": status,
        "wazuh_sightings": wazuh_count,
        "misp_hits": misp_count,
        "executive_summary": md,
        "raw_wazuh_alerts": wazuh_alerts[:5],
        "raw_misp_attributes": misp_hits[:5]
    }

@mcp.tool()
async def investigar_hash(file_hash: str) -> Dict[str, Any]:
    """
    Super-ferramenta SOC autônoma: Investiga um Hash de arquivo (MD5, SHA1 ou SHA256) no Wazuh FIM/Sysmon e no MISP.
    Retorna análise de malware, score de risco e um relatório Markdown executivo.
    """
    wazuh = get_wazuh()
    misp = get_misp()
    
    wazuh_alerts_task = wazuh.search_alerts(file_hash, limit=10)
    misp_hits_task = misp.search_attributes(file_hash)
    
    wazuh_alerts, misp_hits = await asyncio.gather(wazuh_alerts_task, misp_hits_task, return_exceptions=True)
    
    if isinstance(wazuh_alerts, Exception):
        wazuh_alerts = []
    if isinstance(misp_hits, Exception):
        misp_hits = []
        
    wazuh_count = len(wazuh_alerts)
    misp_count = len(misp_hits)
    
    risk_score = min(100, (wazuh_count * 20) + (misp_count * 45))
    status = "MALWARE CONFIRMADO / CRÍTICO" if risk_score >= 70 or misp_count > 0 else ("SUSPEITO" if risk_score >= 20 else "LIMPO / DESCONHECIDO")
    
    md = f"## 🛡️ Dossiê SOC de Investigação de Malware: Hash `{file_hash}`\n\n"
    md += f"**Classificação:** {status}\n"
    md += f"**Risk Score:** `{risk_score}/100`\n\n"
    md += "### 📊 Resumo da Análise\n"
    md += f"- **Detecções de Execução/FIM no Wazuh:** {wazuh_count} ocorrências no ambiente.\n"
    md += f"- **Ocorrências em Base de Ameaças (MISP):** {misp_count} registros encontrados.\n\n"
    
    if wazuh_count > 0:
        md += "### 💻 Agentes Impactados (Wazuh)\n"
        for idx, alert in enumerate(wazuh_alerts[:3], 1):
            agent_name = alert.get("agent", {}).get("name", "Desconhecido")
            desc = alert.get("rule", {}).get("description", "Sem descrição")
            md += f"{idx}. **Agente: `{agent_name}`** - {desc}\n"
        md += "\n"
        
    md += "### ⚡ Recomendações de Contenção\n"
    if risk_score >= 70 or misp_count > 0:
        md += f"- [ ] **Isolar Host:** Executar contenção imediata na máquina afetada via `playbook_isolate_host` ou Active Response.\n"
        md += f"- [ ] **Coleta Forense:** Realizar dump de memória ou quarentena do arquivo executável.\n"
    else:
        md += "- [ ] Submeter o hash para análise adicional em sandbox ou VirusTotal via Cortex.\n"
        
    return {
        "hash": file_hash,
        "risk_score": risk_score,
        "status": status,
        "wazuh_sightings": wazuh_count,
        "misp_hits": misp_count,
        "executive_summary": md
    }

@mcp.tool()
async def investigar_dominio(domain: str) -> Dict[str, Any]:
    """
    Super-ferramenta SOC autônoma: Investiga um domínio/URL nos logs de navegação do Wazuh e inteligência do MISP.
    """
    wazuh = get_wazuh()
    misp = get_misp()
    
    wazuh_alerts, misp_hits = await asyncio.gather(
        wazuh.search_alerts(domain, limit=10),
        misp.search_attributes(domain),
        return_exceptions=True
    )
    if isinstance(wazuh_alerts, Exception): wazuh_alerts = []
    if isinstance(misp_hits, Exception): misp_hits = []
    
    risk_score = min(100, (len(wazuh_alerts) * 15) + (len(misp_hits) * 35))
    status = "DOMÍNIO MALICIOSO / C2" if risk_score >= 70 else ("SUSPEITO" if risk_score >= 30 else "BAIXO RISCO")
    
    md = f"## 🛡️ Dossiê SOC de Domínio: `{domain}`\n\n"
    md += f"**Status:** {status} | **Risk Score:** `{risk_score}/100`\n\n"
    md += f"- **Avistamentos em Logs (Wazuh):** {len(wazuh_alerts)}\n"
    md += f"- **Registros de Threat Intel (MISP):** {len(misp_hits)}\n"
    
    return {
        "domain": domain,
        "risk_score": risk_score,
        "status": status,
        "wazuh_sightings": len(wazuh_alerts),
        "misp_hits": len(misp_hits),
        "executive_summary": md
    }

@mcp.tool()
async def investigar_host(agent_id: str) -> Dict[str, Any]:
    """
    Super-ferramenta SOC autônoma: Compila a postura de segurança completa de um agente Wazuh.
    Coleta dados do Sistema Operacional, Hardware, Processos em execução, Portas abertas, Pacotes e Vulnerabilidades.
    """
    if not get_advanced_wazuh:
        return {"error": "Módulo de ferramentas avançadas do Wazuh não está disponível."}
        
    client = get_advanced_wazuh()
    
    try:
        # Coleta paralela de dados do Syscollector e Agente
        agent_res, os_res, proc_res, ports_res, vuln_res = await asyncio.gather(
            client.get_agents(agent_list=[agent_id]),
            client.get_syscollector_os(agent_id),
            client.get_syscollector_processes(agent_id, limit=5),
            client.get_syscollector_ports(agent_id, limit=5),
            client.get_vulnerabilities(agent_list=[agent_id], limit=5),
            return_exceptions=True
        )
        
        agent_data = agent_res.get("data", {}).get("affected_items", [{}])[0] if not isinstance(agent_res, Exception) else {}
        os_data = os_res.get("data", {}).get("affected_items", [{}])[0] if not isinstance(os_res, Exception) else {}
        procs = proc_res.get("data", {}).get("affected_items", []) if not isinstance(proc_res, Exception) else []
        ports = ports_res.get("data", {}).get("affected_items", []) if not isinstance(ports_res, Exception) else []
        vulns = vuln_res.get("data", {}).get("affected_items", []) if not isinstance(vuln_res, Exception) else []
        
        agent_name = agent_data.get("name", f"Agente {agent_id}")
        agent_status = agent_data.get("status", "Desconhecido")
        agent_ip = agent_data.get("ip", "Desconhecido")
        os_name = os_data.get("name", agent_data.get("os", {}).get("name", "N/A"))
        
        md = f"## 🖥️ Auditoria de Postura do Host: `{agent_name}` (ID: `{agent_id}`)\n\n"
        md += f"- **Status da Conexão:** `{agent_status}` | **IP:** `{agent_ip}`\n"
        md += f"- **Sistema Operacional:** `{os_name}`\n"
        md += f"- **Total de Vulnerabilidades Detectadas (Amostra):** `{len(vulns)}`\n\n"
        
        if vulns:
            md += "### ⚠️ Principais Vulnerabilidades (CVEs)\n"
            for v in vulns[:3]:
                cve = v.get("cve", "CVE-N/A")
                sev = v.get("severity", "N/A")
                title = v.get("title", "Sem título")
                md += f"- **`{cve}` ({sev})**: {title}\n"
            md += "\n"
            
        if ports:
            md += "### 🔌 Portas de Rede Abertas (Top 5)\n"
            for p in ports:
                port_num = p.get("local", {}).get("port", "N/A")
                proto = p.get("protocol", "tcp")
                proc_name = p.get("process", "N/A")
                md += f"- Porta `{port_num}/{proto}` - Processo: `{proc_name}`\n"
            md += "\n"
            
        return {
            "agent_id": agent_id,
            "agent_name": agent_name,
            "status": agent_status,
            "ip": agent_ip,
            "os": os_name,
            "vulnerabilities_sample": vulns,
            "open_ports_sample": ports,
            "running_processes_sample": procs,
            "executive_summary": md
        }
    except Exception as e:
        return {"error": f"Erro ao auditar host {agent_id}: {str(e)}"}

@mcp.tool()
async def triagem_alerta(alert_id: str) -> Dict[str, Any]:
    """
    Super-ferramenta de Inteligência SOC: Realiza triagem automática de um alerta específico do Wazuh.
    Avalia a severidade, mapeia para o MITRE ATT&CK, checa IOCs no MISP e recomenda contenção.
    """
    wazuh = get_wazuh()
    misp = get_misp()
    
    alert = await wazuh.get_alert_by_id(alert_id)
    if not alert:
        return {"error": f"Alerta {alert_id} não encontrado nos logs do Wazuh."}
        
    rule = alert.get("rule", {})
    rule_id = rule.get("id", "N/A")
    level = int(rule.get("level", 0))
    desc = rule.get("description", "Sem descrição")
    mitre_techs = rule.get("mitre", {}).get("id", [])
    
    agent_id = alert.get("agent", {}).get("id", "N/A")
    agent_name = alert.get("agent", {}).get("name", "N/A")
    src_ip = alert.get("data", {}).get("srcip") or alert.get("data", {}).get("win", {}).get("eventdata", {}).get("ipAddress")
    
    # Checar IP no MISP se existir
    misp_hits = []
    if src_ip and src_ip != "127.0.0.1":
        try:
            misp_hits = await misp.search_attributes(src_ip)
        except Exception:
            pass
            
    # Classificação
    if level >= 12 or len(misp_hits) > 0:
        triage_status = "🔴 CRÍTICO - True Positive Provável"
        action_rec = "Isolar Host ou Bloquear IP imediatamente."
    elif level >= 7:
        triage_status = "🟡 ALERTA DE SEVERIDADE MÉDIA - Requer Análise do Analista"
        action_rec = "Verificar comportamento do usuário e logs de auditoria."
    else:
        triage_status = "🟢 BAIXO RISCO / CANDIDATO A FALSO POSITIVO"
        action_rec = "Apenas arquivar ou ajustar tuning da regra se for repetitivo."
        
    md = f"## 🩺 Relatório de Triagem SOC - Alerta ID `{alert_id}`\n\n"
    md += f"**Classificação de Triagem:** {triage_status}\n"
    md += f"**Regra Disparada:** `{rule_id}` (Nível de Severidade: `{level}`)\n"
    md += f"**Descrição:** {desc}\n"
    md += f"**Origem:** Agente `{agent_name}` (ID: `{agent_id}`) | IP Origem: `{src_ip or 'N/A'}`\n\n"
    
    if mitre_techs:
        md += f"**Mapeamento MITRE ATT&CK:** `{', '.join(mitre_techs)}`\n\n"
        
    if misp_hits:
        md += f"⚠️ **ALERTA DE THREAT INTEL:** O IP de origem `{src_ip}` possui `{len(misp_hits)}` registro(s) malicioso(s) no MISP!\n\n"
        
    md += f"### 💡 Ação Recomendada para o SOC\n- -> **{action_rec}**\n"
    
    return {
        "alert_id": alert_id,
        "triage_status": triage_status,
        "rule_level": level,
        "mitre_ids": mitre_techs,
        "misp_matches": len(misp_hits),
        "recommended_action": action_rec,
        "executive_summary": md,
        "raw_alert": alert
    }

@mcp.tool()
async def explicar_mitre(technique_id: str) -> Dict[str, Any]:
    """
    Ferramenta de Base de Conhecimento SOC: Explica uma técnica do MITRE ATT&CK (ex: T1059.001, T1110).
    Mostra o conceito da técnica, como o Wazuh detecta e quais ações o analista deve tomar.
    """
    kb = {
        "T1059": {"name": "Command and Scripting Interpreter", "desc": "Atacantes executam comandos usando PowerShell, Bash ou scripts Python para realizar exploração.", "wazuh_detect": "Regras de Sysmon (Event ID 1) monitorando powershell.exe, cmd.exe ou bash com argumentos suspeitos (-enc, -nop, wget, curl).", "action": "Auditar a linha de comando executada e verificar o processo pai."},
        "T1059.001": {"name": "PowerShell", "desc": "Abuso do PowerShell para executar código malicioso direto em memória ou baixar payloads.", "wazuh_detect": "Regras de PowerShell Script Block Logging (Event ID 4104) ou Sysmon Event ID 1.", "action": "Verificar se o script executado foi autorizado ou isolar a máquina."},
        "T1110": {"name": "Brute Force", "desc": "Tentativas repetidas de adivinhação de senha (SSH, RDP, Web Login) contra uma conta.", "wazuh_detect": "Regras de autenticação falha em janela de tempo (ex: regra 5712 para SSH, regra 60122 para Windows RDP).", "action": "Bloquear o IP atacante usando firewall-drop via Active Response."},
        "T1003": {"name": "OS Credential Dumping", "desc": "Extração de hashes de senha da memória do LSASS (Windows) ou do arquivo /etc/shadow (Linux).", "wazuh_detect": "Regras detectando acesso de leitura ao lsass.exe por ferramentas como Mimikatz ou procdump.", "action": "🔴 CRÍTICO: Isolar o host imediatamente e trocar as credenciais de domínio."},
        "T1078": {"name": "Valid Accounts", "desc": "Uso de credenciais legítimas roubadas para manter acesso e movimentação lateral.", "wazuh_detect": "Logins bem-sucedidos em horários anômalos ou a partir de IPs desconhecidos/maliciosos.", "action": "Revisar logs de autenticação e revogar tokens de sessão do usuário."},
        "T1053": {"name": "Scheduled Task/Job", "desc": "Criação de tarefas agendadas (cron no Linux ou Task Scheduler no Windows) para persistência.", "wazuh_detect": "Regras de FIM em /etc/cron* ou eventos de criação de tarefa no Windows Event Log (4698).", "action": "Remover a tarefa agendada suspeita e auditar quem a criou."}
    }
    
    tech_clean = technique_id.upper().strip()
    info = kb.get(tech_clean) or kb.get(tech_clean.split(".")[0])
    
    if info:
        md = f"## 📘 Enciclopédia MITRE ATT&CK: `{tech_clean}`\n\n"
        md += f"### 📌 Nome: {info['name']}\n"
        md += f"**Descrição:** {info['desc']}\n\n"
        md += f"### 🔍 Como o Wazuh Detecta\n{info['wazuh_detect']}\n\n"
        md += f"### 🛡️ Playbook e Resposta Recomendada\n-> **{info['action']}**\n"
        return {"technique_id": tech_clean, "found": True, "info": info, "executive_summary": md}
    else:
        md = f"## 📘 MITRE ATT&CK: `{tech_clean}`\n\nTécnica específica não encontrada no cache rápido. Recomendado consultar diretamente o portal oficial de regras do Wazuh ou o site do MITRE (attack.mitre.org)."
        return {"technique_id": tech_clean, "found": False, "executive_summary": md}

@mcp.tool()
async def cacada_ip(ip: str) -> Dict[str, Any]:
    """
    Threat Hunting ativo: Varre o histórico global de alertas e comunicações de todos os agentes pelo IP suspeito.
    """
    wazuh = get_wazuh()
    alerts = await wazuh.search_alerts(ip, limit=20)
    
    agents_involved = set()
    for a in alerts:
        ag = a.get("agent", {}).get("name")
        if ag: agents_involved.add(ag)
        
    md = f"## 🏹 Relatório de Threat Hunting: IP `{ip}`\n\n"
    md += f"**Total de Eventos Localizados:** `{len(alerts)}`\n"
    md += f"**Agentes Envolvidos:** `{', '.join(agents_involved) if agents_involved else 'Nenhum'}`\n\n"
    
    if alerts:
        md += "### 📜 Últimos Alertas Encontrados\n"
        for idx, a in enumerate(alerts[:5], 1):
            time_str = a.get("timestamp", "Recente")
            desc = a.get("rule", {}).get("description", "Sem descrição")
            md += f"{idx}. `[{time_str}]` - {desc}\n"
            
    return {
        "ip": ip,
        "total_hits": len(alerts),
        "agents_affected": list(agents_involved),
        "executive_summary": md,
        "raw_alerts": alerts
    }

@mcp.tool()
async def cacada_hash(file_hash: str) -> Dict[str, Any]:
    """
    Threat Hunting ativo: Varre os logs de FIM e execução de processos em todos os agentes pelo Hash suspeito.
    """
    wazuh = get_wazuh()
    alerts = await wazuh.search_alerts(file_hash, limit=20)
    
    agents_involved = set()
    for a in alerts:
        ag = a.get("agent", {}).get("name")
        if ag: agents_involved.add(ag)
        
    md = f"## 🏹 Relatório de Threat Hunting de Hash: `{file_hash}`\n\n"
    md += f"**Total de Ocorrências:** `{len(alerts)}`\n"
    md += f"**Endpoints Afetados:** `{', '.join(agents_involved) if agents_involved else 'Nenhum'}`\n\n"
    
    return {
        "hash": file_hash,
        "total_hits": len(alerts),
        "agents_affected": list(agents_involved),
        "executive_summary": md
    }
