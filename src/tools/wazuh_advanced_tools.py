import asyncio
import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from typing import Dict, Any, List, Optional, Union
from src.tools.server import mcp
from src.config.settings import settings
from soc_mcp_server.config import WazuhConfig
from soc_mcp_server.api.wazuh_client import WazuhClient

_advanced_wazuh_client = None

async def get_advanced_wazuh() -> WazuhClient:
    global _advanced_wazuh_client
    if _advanced_wazuh_client is None:
        w_config = WazuhConfig(
            wazuh_host=settings.WAZUH_HOST,
            wazuh_user=settings.WAZUH_USER,
            wazuh_pass=settings.WAZUH_PASS,
            wazuh_port=settings.WAZUH_API_PORT,
            verify_ssl=False,
            wazuh_indexer_host=settings.WAZUH_INDEXER_HOST,
            wazuh_indexer_port=settings.WAZUH_INDEXER_PORT,
            wazuh_indexer_user=settings.WAZUH_INDEXER_USER,
            wazuh_indexer_pass=settings.WAZUH_INDEXER_PASS,
        )
        _advanced_wazuh_client = WazuhClient(config=w_config)
        await _advanced_wazuh_client.initialize()
    return _advanced_wazuh_client

@mcp.tool()
async def analisar_padroes_alertas(time_range: str, min_frequency: int) -> Dict[str, Any]:
    """Analisa padrões de alertas agregados do Wazuh Indexer."""
    client = await get_advanced_wazuh()
    return await client.analyze_alert_patterns(time_range=time_range, min_frequency=min_frequency)

@mcp.tool()
async def analisar_ameaca_seguranca(indicator: str, indicator_type: str) -> Dict[str, Any]:
    """Analisa ameaças de segurança buscando alertas pelo indicador no Elasticsearch/Indexer."""
    client = await get_advanced_wazuh()
    return await client.analyze_security_threat(indicator=indicator, indicator_type=indicator_type)

@mcp.tool()
async def bloquear_ip_wazuh(ip_address: str, duration: int = 0, agent_id: str = None) -> Dict[str, Any]:
    """Bloqueia um endereço IP executando a resposta ativa firewall-drop."""
    client = await get_advanced_wazuh()
    return await client.block_ip(ip_address=ip_address, duration=duration, agent_id=agent_id)

@mcp.tool()
async def verificar_saude_agente(agent_id: str) -> Dict[str, Any]:
    """Verifica a saúde e o status de um agente do Wazuh."""
    client = await get_advanced_wazuh()
    return await client.check_agent_health(agent_id=agent_id)

@mcp.tool()
async def verificar_reputacao_ioc(indicator: str, indicator_type: str) -> Dict[str, Any]:
    """Verifica a reputação de um IoC buscando no histórico de alertas do Wazuh Indexer."""
    client = await get_advanced_wazuh()
    return await client.check_ioc_reputation(indicator=indicator, indicator_type=indicator_type)

@mcp.tool()
async def desabilitar_usuario_wazuh(agent_id: str, username: str) -> Dict[str, Any]:
    """Desabilita uma conta de usuário no agente via resposta ativa."""
    client = await get_advanced_wazuh()
    return await client.disable_user(agent_id=agent_id, username=username)

@mcp.tool()
async def habilitar_usuario_wazuh(agent_id: str, username: str) -> Dict[str, Any]:
    """Reabilita uma conta de usuário no agente via resposta ativa."""
    client = await get_advanced_wazuh()
    return await client.enable_user(agent_id=agent_id, username=username)

@mcp.tool()
async def resposta_ativa_wazuh(data: Dict) -> Dict[str, Any]:
    """Executa comando de resposta ativa em agentes do Wazuh."""
    client = await get_advanced_wazuh()
    return await client.execute_active_response(data=data)

@mcp.tool()
async def permitir_firewall_wazuh(agent_id: str, src_ip: str) -> Dict[str, Any]:
    """Remove regra de bloqueio de firewall (firewall-drop) via resposta ativa."""
    client = await get_advanced_wazuh()
    return await client.firewall_allow(agent_id=agent_id, src_ip=src_ip)

@mcp.tool()
async def bloquear_firewall_wazuh(agent_id: str, src_ip: str, duration: int = 0) -> Dict[str, Any]:
    """Adiciona regra de bloqueio de firewall (firewall-drop) via resposta ativa."""
    client = await get_advanced_wazuh()
    return await client.firewall_drop(agent_id=agent_id, src_ip=src_ip, duration=duration)

@mcp.tool()
async def gerar_relatorio_seguranca(report_type: str, include_recommendations: bool) -> Dict[str, Any]:
    """Gera relatório consolidado de segurança (CIS, LGPD, NIST)."""
    client = await get_advanced_wazuh()
    return await client.generate_security_report(report_type=report_type, include_recommendations=include_recommendations)

@mcp.tool()
async def obter_configuracao_agente(agent_id: str) -> Dict[str, Any]:
    """Obtém as configurações e grupos do agente."""
    client = await get_advanced_wazuh()
    return await client.get_agent_configuration(agent_id=agent_id)

@mcp.tool()
async def obter_portas_agente(agent_id: str, limit: int) -> Dict[str, Any]:
    """Obtém as portas de rede abertas e escutando no agente."""
    client = await get_advanced_wazuh()
    return await client.get_agent_ports(agent_id=agent_id, limit=limit)

@mcp.tool()
async def obter_processos_agente(agent_id: str, limit: int) -> Dict[str, Any]:
    """Obtém a lista de processos em execução no agente."""
    client = await get_advanced_wazuh()
    return await client.get_agent_processes(agent_id=agent_id, limit=limit)

@mcp.tool()
async def obter_agentes_wazuh(agent_id: Any = None, status: Any = None, limit: Any = 100, kwargs: Dict[str, Any] = None) -> Dict[str, Any]:
    """Lista os agentes cadastrados no gerenciador Wazuh."""
    client = await get_advanced_wazuh()
    return await client.get_agents(agent_id=agent_id, status=status, limit=limit, **kwargs if kwargs else {})

@mcp.tool()
async def obter_resumo_alertas_wazuh(time_range: str, group_by: str) -> Dict[str, Any]:
    """Obtém resumo executivo de alertas agrupados do Wazuh Indexer."""
    client = await get_advanced_wazuh()
    return await client.get_alert_summary(time_range=time_range, group_by=group_by)

@mcp.tool()
async def obter_alertas_wazuh(kwargs: Dict[str, Any] = None) -> Dict[str, Any]:
    """Busca alertas detalhados no índice do Wazuh Indexer."""
    client = await get_advanced_wazuh()
    return await client.get_alerts(**kwargs if kwargs else {})

@mcp.tool()
async def obter_saude_cluster_wazuh() -> Dict[str, Any]:
    """Obtém a saúde geral do cluster do Wazuh."""
    client = await get_advanced_wazuh()
    return await client.get_cluster_health()

@mcp.tool()
async def obter_vulnerabilidades_criticas_wazuh(limit: int) -> Dict[str, Any]:
    """Obtém vulnerabilidades críticas detectadas nos agentes."""
    client = await get_advanced_wazuh()
    return await client.get_critical_vulnerabilities(limit=limit)

@mcp.tool()
async def obter_dados_cti_cve_wazuh(cve_id: str) -> Dict[str, Any]:
    """Obtém dados de inteligência de ameaças (CTI) para um CVE."""
    client = await get_advanced_wazuh()
    return await client.get_cti_data(cve_id=cve_id)

@mcp.tool()
async def buscar_eventos_fim(kwargs: Dict[str, Any] = None) -> Dict[str, Any]:
    """Busca eventos de Monitoramento de Integridade de Arquivos (FIM)."""
    client = await get_advanced_wazuh()
    return await client.get_fim_events(**kwargs if kwargs else {})

@mcp.tool()
async def obter_logs_erro_gerenciador_wazuh(limit: int) -> Dict[str, Any]:
    """Obtém os logs de erro recentes do gerenciador Wazuh."""
    client = await get_advanced_wazuh()
    return await client.get_manager_error_logs(limit=limit)

@mcp.tool()
async def obter_informacoes_gerenciador_wazuh() -> Dict[str, Any]:
    """Obtém informações do gerenciador Wazuh (versão, compilação)."""
    client = await get_advanced_wazuh()
    return await client.get_manager_info()

@mcp.tool()
async def obter_detalhes_regra_wazuh(rule_id: str) -> Dict[str, Any]:
    """Obtém detalhes completos de uma regra de detecção específica."""
    client = await get_advanced_wazuh()
    return await client.get_rule_info(rule_id=rule_id)

@mcp.tool()
async def obter_regras_wazuh(kwargs: Dict[str, Any] = None) -> Dict[str, Any]:
    """Lista as regras de detecção de ameaças do Wazuh."""
    client = await get_advanced_wazuh()
    return await client.get_rules(**kwargs if kwargs else {})

@mcp.tool()
async def obter_agentes_ativos_wazuh() -> Dict[str, Any]:
    """Obtém apenas os agentes que estão com status ativo/conectado."""
    client = await get_advanced_wazuh()
    return await client.get_running_agents()

@mcp.tool()
async def obter_inventario_sistema_agente(agent_id: str, kwargs: Dict[str, Any] = None) -> Dict[str, Any]:
    """Obtém o inventário completo de sistema (Syscollector) do agente."""
    client = await get_advanced_wazuh()
    return await client.get_syscollector_info(agent_id=agent_id, **kwargs if kwargs else {})

@mcp.tool()
async def obter_principais_ameacas_seguranca(limit: int, time_range: str) -> Dict[str, Any]:
    """Obtém as principais ameaças de segurança agrupadas por IPs de origem e agentes."""
    client = await get_advanced_wazuh()
    return await client.get_top_security_threats(limit=limit, time_range=time_range)

@mcp.tool()
async def obter_vulnerabilidades_wazuh(kwargs: Dict[str, Any] = None) -> Dict[str, Any]:
    """Lista as vulnerabilidades identificadas pelo módulo de Vulnerabilidades do Wazuh."""
    client = await get_advanced_wazuh()
    return await client.get_vulnerabilities(**kwargs if kwargs else {})

@mcp.tool()
async def obter_detalhes_vulnerabilidade_wazuh(vuln_id: str, kwargs: Dict[str, Any] = None) -> Dict[str, Any]:
    """Obtém detalhes específicos de uma vulnerabilidade por ID de CVE."""
    client = await get_advanced_wazuh()
    return await client.get_vulnerability_details(vuln_id=vuln_id, **kwargs if kwargs else {})

@mcp.tool()
async def isolar_host_wazuh(agent_id: str) -> Dict[str, Any]:
    """Isola o host da rede cortando tráfego não essencial via resposta ativa."""
    client = await get_advanced_wazuh()
    return await client.isolate_host(agent_id=agent_id)

@mcp.tool()
async def encerrar_processo_wazuh(agent_id: str, process_id: int) -> Dict[str, Any]:
    """Encerra um processo em execução no agente via resposta ativa."""
    client = await get_advanced_wazuh()
    return await client.kill_process(agent_id=agent_id, process_id=process_id)

@mcp.tool()
async def executar_avaliacao_risco(agent_id: str = None) -> Dict[str, Any]:
    """Executa avaliação global de risco calculando score de 0 a 100."""
    client = await get_advanced_wazuh()
    return await client.perform_risk_assessment(agent_id=agent_id)

@mcp.tool()
async def quarentena_arquivo_wazuh(agent_id: str, file_path: str) -> Dict[str, Any]:
    """Move arquivo malicioso para a pasta de quarentena via resposta ativa."""
    client = await get_advanced_wazuh()
    return await client.quarantine_file(agent_id=agent_id, file_path=file_path)

@mcp.tool()
async def reiniciar_servico_wazuh(target: str) -> Dict[str, Any]:
    """Reinicia o serviço do agente ou do gerenciador Wazuh."""
    client = await get_advanced_wazuh()
    return await client.restart_service(target=target)

@mcp.tool()
async def restaurar_arquivo_wazuh(agent_id: str, file_path: str) -> Dict[str, Any]:
    """Restaura um arquivo da quarentena para sua localização original."""
    client = await get_advanced_wazuh()
    return await client.restore_file(agent_id=agent_id, file_path=file_path)

@mcp.tool()
async def executar_comando_resposta_ativa_wazuh(agent_id: str, command: str, parameters: dict = None) -> Dict[str, Any]:
    """Executa comando genérico de resposta ativa informando parâmetros."""
    client = await get_advanced_wazuh()
    return await client.run_active_response(agent_id=agent_id, command=command, parameters=parameters)

@mcp.tool()
async def executar_teste_conformidade(framework: str, agent_id: str = None) -> Dict[str, Any]:
    """Executa verificação de conformidade com base nos dados do SCA (CIS, NIST, LGPD)."""
    client = await get_advanced_wazuh()
    return await client.run_compliance_check(framework=framework, agent_id=agent_id)

@mcp.tool()
async def buscar_logs_gerenciador_wazuh(kwargs: Dict[str, Any] = None) -> Dict[str, Any]:
    """Busca logs do gerenciador com filtros avançados."""
    client = await get_advanced_wazuh()
    return await client.search_logs(**kwargs if kwargs else {})

@mcp.tool()
async def buscar_eventos_seguranca(query: str, time_range: str, limit: int, rule_id: str | None = None, agent_id: str | None = None, level: str | None = None, srcip: str | None = None, dstip: str | None = None) -> Dict[str, Any]:
    """Busca eventos de segurança no Wazuh Indexer utilizando consultas Elasticsearch."""
    client = await get_advanced_wazuh()
    return await client.search_security_events(query=query, time_range=time_range, limit=limit, rule_id=rule_id, agent_id=agent_id, level=level, srcip=srcip, dstip=dstip)

@mcp.tool()
async def desisolar_host_wazuh(agent_id: str) -> Dict[str, Any]:
    """Remove o isolamento de rede do host restaurando a conectividade."""
    client = await get_advanced_wazuh()
    return await client.unisolate_host(agent_id=agent_id)

@mcp.tool()
async def validar_conexao_wazuh() -> Dict[str, Any]:
    """Valida a conectividade e autenticação com as APIs do Wazuh."""
    client = await get_advanced_wazuh()
    return await client.validate_connection()
