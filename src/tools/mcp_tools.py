from fastmcp import FastMCP
import asyncio
from typing import Dict, Any, List

from src.config.settings import settings
from src.integrations.wazuh.client import WazuhClient
from src.integrations.thehive.client import TheHiveClient
from src.integrations.cortex.client import CortexClient
from src.integrations.misp.client import MISPClient
from src.integrations.docker.client import DockerSSHClient

import logging

from src.tools.server import mcp

# Lazily initialized clients
_clients = {}

def get_wazuh() -> WazuhClient:
    if 'wazuh' not in _clients:
        _clients['wazuh'] = WazuhClient()
    return _clients['wazuh']

def get_thehive() -> TheHiveClient:
    if 'thehive' not in _clients:
        _clients['thehive'] = TheHiveClient()
    return _clients['thehive']

def get_cortex() -> CortexClient:
    if 'cortex' not in _clients:
        _clients['cortex'] = CortexClient()
    return _clients['cortex']

def get_misp() -> MISPClient:
    if 'misp' not in _clients:
        _clients['misp'] = MISPClient()
    return _clients['misp']

def get_docker() -> DockerSSHClient:
    if 'docker' not in _clients:
        _clients['docker'] = DockerSSHClient()
    return _clients['docker']


# --- Old Wazuh Tools Removed (Replaced by wazuh_advanced_tools) ---

# --- Ferramentas TheHive ---

@mcp.tool()
async def criar_caso_thehive(title: str, description: str, severity: int = 2) -> Dict[str, Any]:
    """Cria um novo caso de incidente no TheHive."""
    client = get_thehive()
    return await client.create_case(title=title, description=description, severity=severity)

@mcp.tool()
async def listar_casos_thehive(limit: int = 5) -> List[Dict[str, Any]]:
    """Lista os casos de incidentes mais recentes no TheHive."""
    client = get_thehive()
    return await client.list_cases(limit=limit)

@mcp.tool()
async def adicionar_observavel_thehive(case_id: str, data_type: str, data: str, tags: List[str] = None) -> Dict[str, Any]:
    """Adiciona um observável (IOC: IP, Hash, Domínio) a um caso no TheHive."""
    client = get_thehive()
    return await client.add_observable(case_id=case_id, data_type=data_type, data=data, tags=tags)

@mcp.tool()
async def obter_caso_thehive(case_id: str) -> Dict[str, Any]:
    """Obtém detalhes completos de um caso no TheHive pelo ID."""
    client = get_thehive()
    return await client.get_case(case_id=case_id)

@mcp.tool()
async def atualizar_caso_thehive(case_id: str, description: str = None, severity: int = None, status: str = None) -> Dict[str, Any]:
    """Atualiza propriedades (descrição, severidade, status) de um caso no TheHive."""
    client = get_thehive()
    kwargs = {}
    if description is not None:
        kwargs["description"] = description
    if severity is not None:
        kwargs["severity"] = severity
    if status is not None:
        kwargs["status"] = status
    return await client.update_case(case_id=case_id, **kwargs)

@mcp.tool()
async def obter_observaveis_thehive(case_id: str) -> List[Dict[str, Any]]:
    """Obtém todos os observáveis e evidências anexadas a um caso no TheHive."""
    client = get_thehive()
    return await client.get_observables(case_id=case_id)


# --- Ferramentas Cortex ---

@mcp.tool()
async def listar_analisadores_cortex() -> List[Dict[str, Any]]:
    """Lista todos os motores de análise disponíveis no Cortex (VirusTotal, FileScan, etc.)."""
    client = get_cortex()
    return await client.list_analyzers()

@mcp.tool()
async def executar_analise_cortex(analyzer_id: str, data_type: str, data: str) -> Dict[str, Any]:
    """Executa um analisador específico do Cortex em um observável e aguarda o resultado."""
    client = get_cortex()
    
    if len(analyzer_id) != 32:
        analyzers = await client.list_analyzers()
        for a in analyzers:
            if a.get('name') == analyzer_id or a.get('workerDefinitionId') == analyzer_id:
                analyzer_id = a.get('id')
                break
                
    job = await client.run_analyzer(analyzer_id, data_type, data)
    job_id = job.get("id")
    if job_id:
        return await client.wait_for_job(job_id)
    return {"error": "Falha ao iniciar o analisador no Cortex", "detalhes": job}


# --- Ferramentas MISP ---

@mcp.tool()
async def buscar_misp(value: str) -> List[Dict[str, Any]]:
    """Consulta um IOC (IP, Hash, Domínio) na inteligência de ameaças do MISP."""
    client = get_misp()
    return await client.search_attributes(value)

@mcp.tool()
async def publicar_evento_misp(info: str) -> Dict[str, Any]:
    """Cria e publica um novo evento no MISP para uma ameaça confirmada."""
    client = get_misp()
    return await client.add_event(info=info)


# --- Ferramentas Docker & SSH Remotas ---

async def docker_ps() -> List[Dict[str, Any]]:
    """Lista todos os containers Docker em execução no host."""
    client = get_docker()
    return await client.list_containers()

async def docker_logs(container_name: str, tail: int = 100) -> str:
    """Busca logs de um container Docker específico."""
    client = get_docker()
    return await client.get_logs(container_name, tail)

async def docker_restart(container_name: str) -> bool:
    """Reinicia um container Docker específico."""
    client = get_docker()
    return await client.restart_container(container_name)

async def ssh_execute(command: str) -> Dict[str, Any]:
    """Executa um comando de terminal via SSH no servidor host."""
    client = get_docker()
    exit_status, stdout, stderr = await client.ssh.execute(command)
    return {
        "exit_status": exit_status,
        "stdout": stdout,
        "stderr": stderr
    }


@mcp.tool()
async def executar_playbook_soc(alert_data: str) -> Dict[str, Any]:
    """
    Executa o Playbook completo de Analista de SOC em um alerta do Wazuh.
    Analisa o JSON do alerta, extrai IOCs, consulta MISP e Cortex, calcula o Risco e cria um Caso no TheHive.
    """
    import json
    from src.workflows.soc_analyst_workflow import SOCAnalystWorkflow
    try:
        data = json.loads(alert_data) if isinstance(alert_data, str) else alert_data
        workflow = SOCAnalystWorkflow()
        result = await workflow.execute(data)
        return result
    except Exception as e:
        return {"error": str(e)}

@mcp.tool()
async def investigar_alerta_wazuh(alert_id: str) -> Dict[str, Any]:
    """
    Investiga um alerta específico do Wazuh de ponta a ponta.
    Busca o alerta pelo ID (ou 'ultimo'), extrai IOCs, checa MISP/Cortex, calcula o risco e abre um chamado no TheHive.
    """
    from src.workflows.soc_analyst_workflow import SOCAnalystWorkflow
    client = get_wazuh()
    if alert_id.lower() in ["latest", "ultimo", "recente", "last", "critico", "crítico", "ultimo alerta critico", "último", ""]:
        alerts = await client.get_alerts(limit=1, rule_level=10)
        if not alerts:
            alerts = await client.get_alerts(limit=1, rule_level=5)
        if not alerts:
            return {"error": "Nenhum alerta recente encontrado para investigar."}
        alert_data = alerts[0]
    else:
        alert_data = await client.get_alert_by_id(alert_id)
        if not alert_data:
            return {"error": f"Alerta {alert_id} não encontrado nos logs do Wazuh."}
        
    workflow = SOCAnalystWorkflow()
    result = await workflow.execute(alert_data)
    return result

@mcp.tool()
async def responder_incidente_soc(case_id: str, action: str = "block_ip") -> Dict[str, Any]:
    """
    Executa uma ação de resposta ativa em um caso de incidente.
    As ações podem ser 'block_ip' ou 'isolate_host'.
    Lê os observáveis do caso, extrai o IP infrator e dispara a Resposta Ativa no Wazuh.
    """
    hive = get_thehive()
    wazuh = get_wazuh()
    
    observables = await hive.get_observables(case_id)
    if not observables:
        return {"error": "Nenhum observável encontrado no caso."}
        
    results = []
    agent_id = "001"
    case = await hive.get_case(case_id)
    
    if action == "block_ip":
        for obs in observables:
            if obs.get("dataType") == "ip":
                ip = obs.get("data")
                res = await wazuh.run_active_response("000", "firewall-drop", [ip])
                results.append(res)
                await hive.add_case_comment(case_id, f"Automação SOC bloqueou o IP {ip} via Resposta Ativa.")
                
        await hive.update_case_status(case_id, "Resolved", "TruePositive")
        return {"status": "success", "action": action, "active_responses": results}
        
    return {"error": f"Ação {action} não suportada ainda."}

@mcp.tool()
async def cacada_ameacas_threat_hunting(indicator: str) -> Dict[str, Any]:
    """
    Consulta unificada de Threat Hunting entre Wazuh, MISP e TheHive.
    Pesquisa por um IP, Hash ou Domínio em todas as plataformas para montar um dossiê de ameaça.
    """
    wazuh = get_wazuh()
    misp = get_misp()
    hive = get_thehive()
    
    wazuh_hits = await wazuh.search_alerts(indicator, limit=5)
    misp_hits = await misp.search_attributes(indicator)
    
    return {
        "indicador": indicator,
        "detecções_wazuh": len(wazuh_hits),
        "atributos_misp": len(misp_hits),
        "resumo": f"Encontrado {len(wazuh_hits)} vezes nos logs do Wazuh e {len(misp_hits)} vezes na inteligência de ameaças do MISP."
    }

@mcp.tool()
async def gerar_relatorios_incidente(alert_data: str, risk_score: int, iocs: str, case_id: str, misp_hits: int) -> Dict[str, str]:
    """
    Gera relatórios Técnicos e Executivos em Markdown para um incidente de segurança.
    """
    import json
    from src.reports.generator import ReportGenerator
    
    try:
        alert = json.loads(alert_data)
        iocs_list = json.loads(iocs)
        generator = ReportGenerator()
        
        tech_report = generator.generate_technical_report(alert, risk_score, iocs_list, case_id, misp_hits)
        exec_report = generator.generate_executive_report(alert, risk_score)
        
        return {
            "relatorio_tecnico": tech_report,
            "relatorio_executivo": exec_report
        }
    except Exception as e:
        return {"error": str(e)}




