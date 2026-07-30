import asyncio
from typing import Dict, Any, List
import json
import re

from src.utils.logger import logger
from src.tools.mcp_tools import (
    get_wazuh, get_thehive, get_cortex, get_misp,
    add_observable, get_case, update_case, get_observables
)
from src.workflows.ai_soc_analyst import AutonomousAISOCAnalyst

class SOCAnalystWorkflow:
    def __init__(self):
        self.ai_analyst = AutonomousAISOCAnalyst()

    async def execute(self, alert_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        End-to-End SOC Analyst Workflow (100% Autônomo para Produção):
        1. Extração Forense de IOCs do Wazuh Alert
        2. Consulta MISP Threat Intel
        3. Disparo de Analisadores Cortex nos IOCs
        4. Criação/Triagem Inicial de Incidente no TheHive
        5. Investigação Cognitiva AI Analista N1, N2 e N3 (Tomada de Decisão & Contenção)
        """
        alert_id = alert_data.get('id') or str(alert_data.get('timestamp'))
        logger.info(f"Starting SOC Analyst workflow for alert {alert_id}")
        
        # Get rule details
        rule = alert_data.get("rule", {})
        level = int(rule.get("level", alert_data.get("rule_level", 5)))
        rule_desc = rule.get("description", "Alerta de Segurança Detectado no Wazuh")
        rule_id = rule.get("id", "N/A")
        
        # 1. Extract IOCs
        iocs = self._extract_iocs(alert_data)
        logger.info(f"Extracted {len(iocs)} IOCs from alert")

        # 2. Query MISP for each IOC
        misp_results = {}
        for ioc in iocs:
            try:
                hits = await get_misp().search_attributes(ioc['value'])
                misp_results[ioc['value']] = hits
            except Exception as e:
                logger.debug(f"MISP search error for {ioc['value']}: {e}")
                misp_results[ioc['value']] = []
            
        # 3. Run Cortex Analyzers
        cortex_results = {}
        cortex_jobs = []
        try:
            analyzers = await get_cortex().list_analyzers()
            for ioc in iocs[:3]:
                val = ioc['value']
                dtype = ioc['type']
                for az in (analyzers if isinstance(analyzers, list) else []):
                    az_name = az.get("name", "")
                    data_types = az.get("dataTypeList", [])
                    if dtype == "hash" and ("VirusTotal" in az_name or "File" in az_name) and (not data_types or "hash" in data_types):
                        try:
                            job = await get_cortex().run_analyzer(az.get("id", az_name), "hash", val)
                            cortex_jobs.append(job.get("id") or az_name)
                        except Exception:
                            pass
                        break
                    elif dtype == "ip" and ("AbuseIPDB" in az_name or ("VirusTotal" in az_name and "Rescan" not in az_name) or "GeoIP" in az_name) and (not data_types or "ip" in data_types):
                        try:
                            job = await get_cortex().run_analyzer(az.get("id", az_name), "ip", val)
                            cortex_jobs.append(job.get("id") or az_name)
                        except Exception:
                            pass
                        break
            if cortex_jobs:
                cortex_results["jobs_triggered"] = len(cortex_jobs)
        except Exception as e:
            logger.debug(f"Cortex analyzer error: {e}")
        
        # 4. Calculate Risk & Create Case in TheHive
        risk_score = self._calculate_risk(level, misp_results, cortex_results)
        
        case_id = None
        if risk_score >= 50 or level >= 8:
            title = f"[ALERTA WAZUH - NÍVEL {level}] Regra {rule_id}: {rule_desc}"
            desc = self._format_thehive_description(
                alert_data, 
                risk_score, 
                len(iocs), 
                sum(1 for hits in misp_results.values() if hits), 
                len(cortex_jobs)
            )
            severity = 3 if (risk_score >= 80 or level >= 12) else 2
            time_str = str(alert_data.get("timestamp", ""))[:19].replace("T", " ") if alert_data.get("timestamp") else "Agora"
            try:
                # 1. DEDUPLICAÇÃO INTELIGENTE (Evitar casos duplicados no intervalo de 24h da última ocorrência)
                existing_case = await get_thehive().find_duplicate_case(title=title, rule_id=str(rule_id), hours_window=24)
                if existing_case:
                    case_id = existing_case.get("_id") or existing_case.get("caseId")
                    logger.info(f"Smart Deduplication: Alerta duplicado! Reutilizando caso existente {case_id} no TheHive.")
                    try:
                        agent_name = alert_data.get("agent", {}).get("name", "N/A")
                        
                        # 1. Atualizar descrição com a Timeline de Ocorrências no final
                        old_desc = existing_case.get("description", "")
                        new_desc = self._update_recurrence_timeline(old_desc, time_str)
                        await update_case(str(case_id), description=new_desc)
                        
                        # 2. Adicionar comentário no caso
                        comment = f"🔄 **[Alerta Recorrente - {time_str}]**\nNova ocorrência detectada no host `{agent_name}`.\n- **Risk Score:** {risk_score}/100\n- **IOCs Verificados:** {len(iocs)} (Adicionando apenas inéditos às Observações)"
                        await get_thehive().add_case_comment(str(case_id), comment)
                        
                        # 3. Adicionar novos Observables apenas quando forem inéditos (Nunca duplicar)
                        await self._add_unique_observables(str(case_id), iocs)
                    except Exception as ce:
                        logger.warning(f"Erro ao processar recorrência no caso {case_id}: {ce}")
                else:
                    # Inicializar a Timeline na descrição
                    desc_with_timeline = desc + f"\n\n---\n### 🕒 Timeline (Ocorrências Repetidas)\n\n{time_str}\nPrimeira ocorrência.\n\nContador:\n1 ocorrência\nÚltima ocorrência:\n{time_str}"
                    case_tags = self._generate_case_tags(alert_data, level, risk_score, iocs, misp_results)
                    case_response = await get_thehive().create_case(
                        title=title, 
                        description=desc_with_timeline, 
                        severity=severity, 
                        tags=case_tags
                    )
                    case_id = case_response.get("id") or case_response.get("caseId") or f"CASE-{alert_id[:8]}"
                    logger.info(f"Successfully created TheHive case: {case_id} with tags: {case_tags}")
                    
                    if case_id and not str(case_id).startswith("CASE-") and not str(case_id).startswith("LOCAL-"):
                        try:
                            task_desc = (
                                f"### 🕒 Timestamp da Detecção\n`{time_str}`\n\n"
                                f"### 📋 Log Completo da Detecção\n```json\n{json.dumps(alert_data, indent=2, ensure_ascii=False)}\n```"
                            )
                            task_resp = await get_thehive().create_task(
                                case_id=str(case_id),
                                title="Detecção",
                                description=task_desc,
                                status="Waiting"
                            )
                            task_id = task_resp.get("_id") or task_resp.get("id")
                            if task_id:
                                await get_thehive().add_task_log(str(task_id), task_desc)
                        except Exception as te:
                            logger.warning(f"Erro ao criar tarefa inicial de Detecção no caso {case_id}: {te}")
                
                if case_id and not str(case_id).startswith("CASE-") and not str(case_id).startswith("LOCAL-"):
                    await self._add_unique_observables(str(case_id), iocs)
            except Exception as e:
                logger.error(f"Failed to create/update TheHive case: {e}")
                case_id = f"LOCAL-CASE-{rule_id}"
                
        # 5. INVESTIGAÇÃO COGNITIVA AI ANALYST N1, N2 E N3 AUTÔNOMA
        logger.info("Executando investigação autônoma do AI SOC Analyst (N1/N2/N3)...")
        ai_result = await self.ai_analyst.investigate_and_respond(alert_data, misp_results, cortex_results, str(case_id))
                    
        return {
            "status": "success",
            "risk_score": risk_score,
            "case_id": case_id,
            "ai_verdict": ai_result.get("verdict"),
            "ai_report": ai_result.get("report")
        }

    def _extract_iocs(self, data: Dict[str, Any]) -> List[Dict[str, str]]:
        iocs = []
        text = json.dumps(data)
        ips = re.findall(r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b', text)
        for ip in ips:
            if ip not in ["127.0.0.1", "0.0.0.0", "255.255.255.255"]:
                iocs.append({"type": "ip", "value": ip})
        
        md5s = re.findall(r'\b[a-fA-F0-9]{32}\b', text)
        for md5 in md5s:
            iocs.append({"type": "hash", "value": md5})
            
        sha256s = re.findall(r'\b[a-fA-F0-9]{64}\b', text)
        for sha in sha256s:
            iocs.append({"type": "hash", "value": sha})
            
        urls = re.findall(r'https?://[^\s<>"\'\)]+', text)
        for url in urls:
            iocs.append({"type": "url", "value": url})
            
        emails = re.findall(r'\b[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}\b', text)
        for email in emails:
            iocs.append({"type": "other", "value": email})
            
        files = re.findall(r'\b[\w\-. ]+\.(?:exe|dll|bat|ps1|vbs|lnk|docx|doc|xls|xlsx|pdf|scr|tmp|bin|msi|vbe|js|wsf|hta)\b', text, re.IGNORECASE)
        for f in files:
            if len(f) > 4 and not f.lower().endswith((".com", ".net", ".org", ".edu", ".gov", ".br")):
                iocs.append({"type": "filename", "value": f.strip()})
            
        unique_iocs = [dict(t) for t in {tuple(d.items()) for d in iocs}]
        return unique_iocs

    async def _add_unique_observables(self, case_id: str, iocs: List[Dict[str, Any]]):
        """Adicionar novos Observables apenas quando forem inéditos. Nunca duplicar Observables já existentes."""
        try:
            existing_obs = await get_observables(str(case_id))
            existing_vals = {str(obs.get("data", "")).lower().strip() for obs in (existing_obs if isinstance(existing_obs, list) else [])}
        except Exception:
            existing_vals = set()

        for ioc in iocs:
            val = str(ioc['value']).strip()
            if not val or val.lower() in existing_vals:
                continue
            try:
                await add_observable(str(case_id), ioc['type'], val, tags=["auto-extracted", "wazuh", f"ioc:{ioc['type']}"])
                existing_vals.add(val.lower())
                logger.info(f"Adicionado observable inédito ao caso {case_id}: [{ioc['type']}] {val}")
            except Exception as e:
                logger.debug(f"Observable [{ioc['type']}] {val} não adicionado (possível duplicidade): {e}")

    def _update_recurrence_timeline(self, desc: str, new_time_str: str) -> str:
        """Deixe sempre no final das descrições os alertas repetidos no formato Timeline e Contador."""
        marker = "### 🕒 Timeline (Ocorrências Repetidas)"
        if marker not in desc:
            return desc + f"\n\n---\n{marker}\n\n{new_time_str}\nPrimeira ocorrência.\n\nContador:\n1 ocorrência\nÚltima ocorrência:\n{new_time_str}"
        
        parts = desc.split(marker)
        base_desc = parts[0].rstrip()
        if base_desc.endswith("---"):
            base_desc = base_desc[:-3].rstrip()
        timeline_sec = parts[1]
        
        lines = [line.strip() for line in timeline_sec.splitlines() if line.strip()]
        occ_pairs = []
        i = 0
        while i < len(lines):
            line = lines[i]
            if "Contador:" in line:
                break
            if len(line) >= 8 and any(char.isdigit() for char in line):
                label = lines[i+1] if (i+1 < len(lines) and "ocorrência" in lines[i+1].lower()) else "Nova ocorrência detectada."
                occ_pairs.append((line, label))
                i += 2
            else:
                i += 1
                
        occ_pairs.append((new_time_str, "Nova ocorrência detectada."))
        count = len(occ_pairs)
        
        timeline_str = f"\n\n---\n{marker}\n\n"
        for t, l in occ_pairs:
            timeline_str += f"{t}\n{l}\n\n"
            
        timeline_str += f"Contador:\n{count} ocorrências\nÚltima ocorrência:\n{new_time_str}"
        return base_desc + timeline_str

    def _generate_case_tags(self, alert_data: Dict[str, Any], level: int, risk_score: int, iocs: List[Dict[str, Any]], misp_results: Dict[str, Any]) -> List[str]:
        tags = set()
        rule = alert_data.get("rule", {})
        rule_desc = str(rule.get("description", "")).lower()
        groups = [str(g).lower() for g in rule.get("groups", [])]
        agent_name = str(alert_data.get("agent", {}).get("name", "")).lower()
        full_text = json.dumps(alert_data).lower()

        # 1. Severidade
        if level >= 13 or risk_score >= 80:
            tags.add("severity:critical")
        elif level >= 10 or risk_score >= 60:
            tags.add("severity:high")
        elif level >= 7 or risk_score >= 40:
            tags.add("severity:medium")
        elif level >= 3:
            tags.add("severity:low")
        else:
            tags.add("severity:informational")

        # 2. Level
        tags.add(f"level:level-{level}")
        tags.add(f"level-{level}")

        # 3. Origem do alerta
        tags.add("source:wazuh")
        if any("sysmon" in g for g in groups) or "sysmon" in full_text:
            tags.add("source:sysmon")
        if any("defender" in g for g in groups) or "defender" in full_text:
            tags.add("source:windows-defender")
            tags.add("source:microsoft-defender")
        if any("suricata" in g for g in groups) or "suricata" in full_text:
            tags.add("source:suricata")
        if any("osquery" in g for g in groups) or "osquery" in full_text:
            tags.add("source:osquery")
        if any("crowdstrike" in g for g in groups) or "crowdstrike" in full_text:
            tags.add("source:crowdstrike")
        tags.add("source:cortex")
        tags.add("source:misp")

        # 4. Tipo de incidente
        if "ransomware" in rule_desc or any("ransomware" in g for g in groups):
            tags.add("type:ransomware")
        elif any(w in rule_desc for w in ["malware", "dropped", "trojan", "virus", "suspicious file", "backdoor", "spyware"]):
            tags.add("type:malware")
            if "backdoor" in rule_desc: tags.add("type:backdoor")
            if "trojan" in rule_desc: tags.add("type:trojan")
        elif any(w in rule_desc for w in ["brute force", "bruteforce", "authentication failed", "password"]):
            tags.add("type:bruteforce")
            tags.add("type:credential-theft")
        elif any(w in rule_desc for w in ["phishing", "spear", ".lnk", "word", "office", "excel"]):
            tags.add("type:phishing")
            tags.add("type:spear-phishing")
        elif any(w in rule_desc for w in ["injection", "remote desktop", "lsass", "privilege", "escalation"]):
            tags.add("type:privilege-escalation")
            tags.add("type:lateral-movement")
        elif any(w in rule_desc for w in ["powershell", "script", "vbeui", "cmd", "wscript", "cscript"]):
            tags.add("type:powershell")
            tags.add("type:command-and-control")
        elif "sql" in rule_desc or "injection" in rule_desc:
            tags.add("type:sql-injection")
            tags.add("type:web-attack")
        elif "xss" in rule_desc or "cross-site" in rule_desc:
            tags.add("type:xss")
            tags.add("type:web-attack")
        elif any(w in rule_desc for w in ["dos", "ddos", "flood", "denial of service"]):
            tags.add("type:dos")
            tags.add("type:ddos")
        elif any(w in rule_desc for w in ["user added", "group added", "persistence", "registry"]):
            tags.add("type:persistence")
        elif any(w in rule_desc for w in ["exfiltration", "data leak", "steal"]):
            tags.add("type:exfiltration")
            tags.add("type:data-leak")
        else:
            tags.add("type:security-alert")

        # 5. MITRE ATT&CK
        mitre_ids = rule.get("mitre", {}).get("id", [])
        if isinstance(mitre_ids, list):
            for m_id in mitre_ids:
                tags.add(f"mitre:{m_id}")
        elif isinstance(mitre_ids, str):
            tags.add(f"mitre:{mitre_ids}")
        if "type:phishing" in tags: tags.update(["mitre:T1566", "mitre:T1027"])
        if "type:bruteforce" in tags: tags.add("mitre:T1110")
        if "type:powershell" in tags: tags.add("mitre:T1059")
        if "type:lateral-movement" in tags: tags.add("mitre:T1021")
        if "type:privilege-escalation" in tags: tags.add("mitre:T1055")

        # 6. Sistema afetado
        if any(w in groups for w in ["windows", "sysmon"]) or "win" in rule_desc or "desktop-" in agent_name or "c:\\" in full_text:
            tags.add("os:windows")
        elif any(w in groups for w in ["linux", "sshd", "syslog", "pam"]) or "sshd" in rule_desc or "root" in rule_desc or "/" in str(alert_data.get("data", {})):
            tags.add("os:linux")
        else:
            tags.add("os:windows")
            tags.add("os:linux")

        # 7. Estado do caso
        tags.add("state:triage")
        tags.add("state:investigating")
        tags.add("state:auto-response")

        # 8. IOC
        has_ioc = False
        for ioc in iocs:
            itype = ioc.get("type", "")
            if itype == "ip": tags.add("ioc:ip"); has_ioc = True
            elif itype == "hash":
                tags.add("ioc:hash")
                val = str(ioc.get("value", ""))
                if len(val) == 64: tags.add("ioc:sha256")
                elif len(val) == 32: tags.add("ioc:md5")
                has_ioc = True
            elif itype == "domain": tags.add("ioc:domain"); tags.add("ioc:dns"); has_ioc = True
            elif itype == "url": tags.add("ioc:url"); has_ioc = True
        if "process" in rule_desc or ".exe" in full_text: tags.add("ioc:process"); has_ioc = True
        if "registry" in rule_desc or "hklm" in full_text or "hkcu" in full_text: tags.add("ioc:registry"); has_ioc = True
        if "email" in full_text or "@" in full_text: tags.add("ioc:email")
        if "hostname" in full_text or "desktop-" in agent_name: tags.add("ioc:hostname")
        if not has_ioc:
            tags.add("ioc:no-ioc")

        # 9. Threat Intelligence
        if any(hits for hits in misp_results.values()):
            tags.add("ti:known-malicious")
            tags.add("ti:ioc")
            tags.add("ti:ti")
        else:
            tags.add("ti:unknown")
            tags.add("ti:ioc")
            tags.add("ti:ti")

        # 11. Compliance
        tags.update(["compliance:nist", "compliance:cis", "compliance:iso27001", "compliance:lgpd", "compliance:pci-dss"])
        if any("pci" in g for g in groups): tags.add("compliance:pci-dss")
        if any("gdpr" in g or "lgpd" in g for g in groups): tags.add("compliance:lgpd")
        if any("nist" in g for g in groups): tags.add("compliance:nist")
        if any("cis" in g for g in groups): tags.add("compliance:cis")

        # 12. Resposta
        tags.add("response:auto-response")

        return sorted(list(tags))

    def _calculate_risk(self, level: int, misp_res: Dict[str, Any], cortex_res: Dict[str, Any]) -> int:
        score = level * 6
        for ioc, hits in misp_res.items():
            if hits:
                score += 30
        if cortex_res.get("jobs_triggered", 0) > 0:
            score += 10
        return min(max(score, 10), 100)

    def _format_thehive_description(self, alert_data: Dict[str, Any], risk_score: int, len_iocs: int, misp_hits: int, cortex_jobs: int) -> str:
        rule = alert_data.get("rule", {})
        agent = alert_data.get("agent", {})
        manager = alert_data.get("manager", {})
        predecoder = alert_data.get("predecoder", {})
        decoder = alert_data.get("decoder", {})
        data = alert_data.get("data", {})
        
        lines = [
            "### 🤖 Sumário SOC AI Orchestrator",
            "| key | val |",
            "|---|---|",
            f"| **Severidade (Nível Wazuh)** | {rule.get('level', 'N/A')} |",
            f"| **Risk Score Calculado** | {risk_score} / 100 |",
            f"| **IOCs Extraídos** | {len_iocs} |",
            f"| **Ocorrências no MISP** | {misp_hits} |",
            f"| **Trabalhos Cortex Disparados** | {cortex_jobs} |",
            "",
            "### Timestamp",
            "| key | val |",
            "|---|---|",
            f"| **timestamp** | {alert_data.get('timestamp', 'N/A')} |",
            "",
            "### Rule",
            "| key | val |",
            "|---|---|"
        ]
        
        for k, v in rule.items():
            if k == "mitre" and isinstance(v, dict):
                for mk, mv in v.items():
                    lines.append(f"| **rule.mitre.{mk}** | `{mv}` |")
            elif isinstance(v, (list, dict)):
                lines.append(f"| **rule.{k}** | `{v}` |")
            else:
                lines.append(f"| **rule.{k}** | {v} |")
                
        if agent:
            lines.extend([
                "",
                "### Agent",
                "| key | val |",
                "|---|---|"
            ])
            for k, v in agent.items():
                lines.append(f"| **agent.{k}** | {v} |")
                
        if manager:
            lines.extend([
                "",
                "### Manager",
                "| key | val |",
                "|---|---|"
            ])
            for k, v in manager.items():
                lines.append(f"| **manager.{k}** | {v} |")
                
        lines.extend([
            "",
            "### Id",
            "| key | val |",
            "|---|---|",
            f"| **id** | {alert_data.get('id', 'N/A')} |"
        ])
        
        if alert_data.get("full_log"):
            lines.extend([
                "",
                "### Full_log",
                "| key | val |",
                "|---|---|",
                f"| **full_log** | `{alert_data.get('full_log')}` |"
            ])
            
        if predecoder:
            lines.extend([
                "",
                "### Predecoder",
                "| key | val |",
                "|---|---|"
            ])
            for k, v in predecoder.items():
                lines.append(f"| **predecoder.{k}** | {v} |")
                
        if decoder:
            lines.extend([
                "",
                "### Decoder",
                "| key | val |",
                "|---|---|"
            ])
            for k, v in decoder.items():
                lines.append(f"| **decoder.{k}** | {v} |")
                
        if data:
            lines.extend([
                "",
                "### Data",
                "| key | val |",
                "|---|---|"
            ])
            def _flatten_dict(d, prefix="data"):
                items = []
                for k, v in d.items():
                    new_key = f"{prefix}.{k}" if prefix else k
                    if isinstance(v, dict):
                        items.extend(_flatten_dict(v, new_key))
                    else:
                        items.append((new_key, v))
                return items
                
            for fk, fv in _flatten_dict(data):
                val_str = f"`{fv}`" if isinstance(fv, (list, dict)) else str(fv)
                lines.append(f"| **{fk}** | {val_str} |")
                
        if alert_data.get("location"):
            lines.extend([
                "",
                "### Location",
                "| key | val |",
                "|---|---|",
                f"| **location** | {alert_data.get('location')} |"
            ])
            
        return "\n".join(lines)
