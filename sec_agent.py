#!/usr/bin/env python3
"""
sec_agent.py - Agente orquestrador de segurança (MVP) — versão aprimorada.

Funcionalidades principais:
 - Orquestra ZAP (via Docker) para varredura DAST.
 - Integração com AFL/AFL++ (fuzzer binário) — recomendado rodar em WSL2/Ubuntu no Windows.
 - Stub para Burp (documenta como integrar).
 - Gerador simples de payloads / mutator (pequeno motor de fuzzing leve).
 - Normalização de achados e criação opcional de issues no GitHub.
"""
import os
import sys
import yaml
import json
import shutil
import time
import argparse
import logging
import subprocess
from pathlib import Path
from dataclasses import dataclass, field
from typing import List, Dict, Any, Optional
from dotenv import load_dotenv
import requests
import hashlib

# ------------------------
# Configuração de logging
# ------------------------
LOG = logging.getLogger("sec_agent")
LOG.setLevel(logging.DEBUG)
ch = logging.StreamHandler(sys.stdout)
ch.setLevel(logging.INFO)
formatter = logging.Formatter("%(asctime)s %(levelname)s %(message)s")
ch.setFormatter(formatter)
LOG.addHandler(ch)
load_dotenv()

def run_cmd(cmd: List[str], check=True, capture_output=False, env=None, cwd=None, timeout=None):
    """
    Executa comando via subprocess, registra e retorna resultado.
    - capture_output True -> retorna dict com stdout/stderr/returncode
    - se check=True e returncode != 0 -> levanta CalledProcessError
    Nota: aqui usamos check=False internamente ao chamar subprocess.run para evitar
    abortar imediatamente em exit codes que representam "achados" (ex.: ZAP).
    """
    LOG.debug("RUN: %s", " ".join(cmd))
    try:
        # sempre capturamos output para podermos logar
        res = subprocess.run(cmd, check=False, capture_output=True, text=True, env=env, cwd=cwd, timeout=timeout)
        # registrar alerta se houver código diferente de zero (pode ser apenas achados do scanner)
        if res.returncode != 0:
            LOG.warning("Comando retornou exit code %s: %s", res.returncode, " ".join(cmd))
            LOG.debug("STDOUT (prefixo): %s", (res.stdout or "")[:2000])
            LOG.debug("STDERR (prefixo): %s", (res.stderr or "")[:2000])
        if capture_output:
            return {"stdout": res.stdout, "stderr": res.stderr, "returncode": res.returncode}
        return res
    except subprocess.CalledProcessError as exc:
        # log mais detalhado para debugging
        try:
            out = exc.stdout if hasattr(exc, "stdout") else None
            err = exc.stderr if hasattr(exc, "stderr") else None
            LOG.error("Comando falhou (code=%s): %s\nSTDOUT: %s\nSTDERR: %s", exc.returncode, " ".join(cmd), (out or "")[:2000], (err or "")[:2000])
        except Exception:
            LOG.error("Comando falhou: %s", exc)
        raise
    except Exception as e:
        LOG.error("Erro ao executar comando %s: %s", " ".join(cmd), e)
        raise

def ensure_dir(p: Path):
    """
    Garante que o diretório existe (cria recursivamente se necessário).
    """
    if not p.exists():
        p.mkdir(parents=True, exist_ok=True)

# ------------------------
# Dataclass de configuração
# ------------------------
@dataclass
class AgentConfig:
    target_urls: List[str]
    off_limits: List[str] = field(default_factory=list)
    reports_dir: str = "sec-reports"
    workspace_dir: str = "sec-work"
    zap: Dict[str, Any] = field(default_factory=lambda: {"enabled": True})
    afl: Dict[str, Any] = field(default_factory=lambda: {"enabled": True})
    burp: Dict[str, Any] = field(default_factory=lambda: {"enabled": False})
    generator: Dict[str, Any] = field(default_factory=lambda: {"enabled": True})
    github: Dict[str, Any] = field(default_factory=dict)
    max_runtime_seconds: int = 3600

    @staticmethod
    def load(path: str):
        with open(path, "r", encoding="utf-8") as f:
            j = yaml.safe_load(f)
        return AgentConfig(**j)

# ------------------------
# Checklist pré-execução
# ------------------------
def checklist(config: AgentConfig):
    LOG.info("Executando checklist pré-scan...")
    LOG.info("Alvos: %s", config.target_urls)
    LOG.info("Off-limits: %s", config.off_limits)
    LOG.info("Diretório de relatórios: %s", config.reports_dir)
    auth_file = Path(config.workspace_dir) / "authorization.txt"
    if not auth_file.exists():
        LOG.warning("Arquivo de autorização não encontrado em %s. Crie-o antes de scans agressivos.", auth_file)
    else:
        LOG.info("Arquivo de autorização encontrado: %s", auth_file)
    ensure_dir(Path(config.reports_dir))
    ensure_dir(Path(config.workspace_dir))
    LOG.info("Checklist completo.")

# ------------------------
# Runner ZAP (via Docker)
# ------------------------
class ZAPRunner:
    def __init__(self, config: AgentConfig):
        self.config = config
        self.reports_dir = Path(config.reports_dir)
        ensure_dir(self.reports_dir)

    def docker_available(self) -> bool:
        try:
            # tenta docker --version e também which docker
            run_cmd(["docker", "--version"], check=True, capture_output=True)
            return True
        except Exception:
            try:
                res = run_cmd(["which", "docker"], check=False, capture_output=True)
                return bool(res.get("stdout").strip())
            except Exception:
                return False

    def baseline_scan(self, target: str, report_name_prefix: Optional[str] = None, extra_args: List[str] = []):
        """
        Executa 'zap-baseline.py' dentro da imagem oficial OWASP ZAP via Docker.
        Produz HTML e JSON no diretório de relatórios (montado como /zap/wrk/).
        """
        if not self.docker_available():
            LOG.error("Docker não disponível; não é possível rodar o container ZAP.")
            return None

        ts = int(time.time())
        if not report_name_prefix:
            report_name_prefix = hashlib.sha1(target.encode()).hexdigest()[:8]
        html_out = self.reports_dir / f"zap_{report_name_prefix}_{ts}.html"
        json_out = self.reports_dir / f"zap_{report_name_prefix}_{ts}.json"

        # Monta volume: reports_dir (host) -> /zap/wrk/ (container) com rw explícito
        host_reports = str(self.reports_dir.resolve())
        cmd = [
            "docker", "run", "--rm",
            "-v", f"{host_reports}:/zap/wrk:rw",
            "ghcr.io/zaproxy/zaproxy:stable",
            "zap-baseline.py",
            "-t", target,
            "-r", f"/zap/wrk/{html_out.name}",
            "-J", f"/zap/wrk/{json_out.name}"
        ] + extra_args

        LOG.info("Iniciando ZAP baseline para %s (saida: %s)", target, html_out)
        try:
            # capturar saída para log; note check=False já dentro de run_cmd
            res = run_cmd(cmd, check=False, capture_output=True, timeout=self.config.max_runtime_seconds)
            # se res veio como dict (capture_output=True), tratar adequadamente
            if isinstance(res, dict):
                return_code = res.get("returncode")
                LOG.info("ZAP baseline finalizado (returncode=%s). Arquivo JSON: %s", return_code, json_out)
            else:
                # objeto subprocess.CompletedProcess
                return_code = getattr(res, "returncode", None)
                LOG.info("ZAP baseline finalizado (returncode=%s). Arquivo JSON: %s", return_code, json_out)
            # tentar retornar caminhos mesmo que exitcode !=0 (ZAP grava JSON quando encontra alertas)
            return {"html": str(html_out), "json": str(json_out)}
        except Exception as e:
            LOG.error("ZAP baseline falhou: %s", e)
            return None

    def parse_zap_json(self, json_path: str) -> List[Dict[str, Any]]:
        """
        Parse robusto do JSON gerado pelo ZAP para extrair alerts.
        Suporta variações de estrutura entre versões do ZAP.
        """
        if not os.path.exists(json_path):
            LOG.error("ZAP JSON não encontrado: %s", json_path)
            return []
        with open(json_path, "r", encoding="utf-8") as f:
            try:
                data = json.load(f)
            except Exception as e:
                LOG.error("Falha ao ler JSON do ZAP: %s", e)
                return []

        alerts = []

        # Estrutura comum: data["site"] -> list of sites, each with "alerts"
        sites = data.get("site") or data.get("sites") or []
        if isinstance(sites, dict):
            sites = [sites]

        if sites:
            for site in sites:
                site_alerts = site.get("alerts") or site.get("alert") or []
                for a in site_alerts:
                    # instances pode ser lista de dicts ou vazio
                    instances = a.get("instances") or a.get("instancesList") or []
                    uri = ""
                    if isinstance(instances, list) and len(instances) > 0:
                        first = instances[0]
                        if isinstance(first, dict):
                            uri = first.get("uri") or first.get("url") or ""
                        else:
                            uri = str(first)
                    alerts.append({
                        "name": a.get("name") or a.get("alert"),
                        "risk": a.get("risk") or a.get("riskdesc") or a.get("severity"),
                        "confidence": a.get("confidence"),
                        "url": uri,
                        "evidence": a.get("evidence") or a.get("evidenceList"),
                        "desc": a.get("description") or a.get("desc") or a.get("detail")
                    })
        else:
            # fallback: procurar por "alerts" direto no root
            root_alerts = data.get("alerts") or []
            for a in root_alerts:
                instances = a.get("instances") or []
                uri = ""
                if instances:
                    first = instances[0]
                    uri = first.get("uri") if isinstance(first, dict) else str(first)
                alerts.append({
                    "name": a.get("name"),
                    "risk": a.get("risk"),
                    "confidence": a.get("confidence"),
                    "url": uri,
                    "evidence": a.get("evidence"),
                    "desc": a.get("description")
                })

        LOG.info("Parseado %d alerts do JSON do ZAP", len(alerts))
        return alerts

# ------------------------
# Runner AFL (fuzzer binário)
# ------------------------
class AFLRunner:
    def __init__(self, config: AgentConfig):
        self.config = config
        self.workdir = Path(config.workspace_dir) / "afl"
        ensure_dir(self.workdir)

    def afl_available(self) -> bool:
        """
        Verifica se 'afl-fuzz' está disponível no PATH.
        """
        try:
            # tenta localizar no PATH
            res = run_cmd(["which", "afl-fuzz"], check=False, capture_output=True)
            if isinstance(res, dict):
                out = res.get("stdout", "")
            else:
                out = getattr(res, "stdout", "")
            if out and out.strip():
                return True
            # tentativa fallback: executar com -h (pode falhar se não instalado)
            run_cmd(["afl-fuzz", "-h"], check=False, capture_output=True)
            return True
        except Exception:
            return False

    def prepare_seeds(self, seeds_dir: str, seed_contents: Dict[str, bytes]):
        sdir = self.workdir / seeds_dir
        ensure_dir(sdir)
        for name, data in seed_contents.items():
            with open(sdir / name, "wb") as f:
                f.write(data)
        LOG.info("Preparado %d arquivos seed em %s", len(seed_contents), sdir)
        return str(sdir)

    def run_fuzz(self, target_cmd: List[str], seeds_dir: str, out_dir_name: str = "findings", timeout: int = 300):
        """
        Executa afl-fuzz por 'timeout' segundos (simples), retorna path do out_dir.
        """
        if not self.afl_available():
            LOG.error("afl-fuzz não disponível; instale AFL/AFL++ ou execute externamente.")
            return None
        out_dir = self.workdir / out_dir_name
        ensure_dir(out_dir)

        log_stdout = out_dir / "afl_stdout.log"
        log_stderr = out_dir / "afl_stderr.log"

        cmd = ["afl-fuzz", "-i", seeds_dir, "-o", str(out_dir)] + ["--"] + target_cmd
        LOG.info("Iniciando afl-fuzz: %s", " ".join(cmd))
        # rodar em subprocess e gravar logs
        with open(log_stdout, "w", encoding="utf-8") as so, open(log_stderr, "w", encoding="utf-8") as se:
            proc = subprocess.Popen(cmd, stdout=so, stderr=se, text=True)
            try:
                start = time.time()
                while True:
                    if proc.poll() is not None:
                        LOG.info("Processo afl-fuzz finalizou (code %s). Ver logs em %s", proc.returncode, out_dir)
                        break
                    if time.time() - start > timeout:
                        LOG.info("Tempo limite atingido para afl-fuzz; terminando...")
                        proc.terminate()
                        break
                    time.sleep(2)
                return {"out_dir": str(out_dir)}
            except Exception as e:
                LOG.error("Erro ao rodar afl-fuzz: %s", e)
                proc.kill()
                return None

# ------------------------
# Burp stub (documentação de integração)
# ------------------------
class BurpRunner:
    def __init__(self, config: AgentConfig):
        self.config = config

    def note(self):
        LOG.info("Integração com Burp é um stub. Para integrar Burp Pro/Enterprise:")
        LOG.info("- Execute o Burp em VM/container com licença.")
        LOG.info("- Use API REST do Burp para iniciar scans e exportar JSON.")
        LOG.info("Este agente fornece um placeholder para orchestrar Burp.")

# ------------------------
# Gerador simples de payloads / mutator
# ------------------------
class PayloadGenerator:
    def __init__(self, config: AgentConfig):
        self.config = config
        self.simple_payloads = [
            "' OR '1'='1",
            "<script>alert(1)</script>",
            "../../../../etc/passwd",
            "%00",
            "'; DROP TABLE users; --",
            '{"name": "injected", "age": -1}',
        ]

    def mutate(self, seed: str) -> str:
        muts = [
            lambda s: s + s[::-1],
            lambda s: s + " " + hashlib.sha1(s.encode()).hexdigest()[:8],
            lambda s: "'" + s + "' OR '1'='1",
            lambda s: s.replace(" ", "%20"),
            lambda s: s + "\x00"
        ]
        import random
        f = random.choice(muts)
        return f(seed)

    def generate(self, n: int = 50) -> List[str]:
        LOG.info("Gerando até %d payloads (mutators + seeds)", n)
        out = []
        seeds = list(self.simple_payloads)
        i = 0
        while len(out) < n:
            base = seeds[i % len(seeds)]
            out.append(self.mutate(base))
            i += 1
        return out

# ------------------------
# Triage e relatório
# ------------------------
class Triage:
    def __init__(self, config: AgentConfig):
        self.config = config

    def normalize_alerts(self, alerts: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        norm = []
        for a in alerts:
            risk_map = {"Low": 1, "Medium": 2, "High": 3, "Critical": 4,
                        "low": 1, "medium": 2, "high": 3, "critical": 4,
                        "Informational": 0, "informational": 0}
            raw_risk = a.get("risk") or ""
            score = risk_map.get(raw_risk, risk_map.get(raw_risk.strip().lower(), 1))
            norm.append({
                "title": a.get("name"),
                "risk": a.get("risk"),
                "score": score,
                "url": a.get("url"),
                "evidence": a.get("evidence") or a.get("desc"),
                "desc": a.get("desc")
            })
        norm.sort(key=lambda x: x["score"], reverse=True)
        LOG.info("Normalizados %d alerts", len(norm))
        return norm

    def save_report(self, norm_alerts: List[Dict[str, Any]], out_path: str):
        ensure_dir(Path(out_path).parent)
        with open(out_path, "w", encoding="utf-8") as f:
            json.dump(norm_alerts, f, indent=2, ensure_ascii=False)
        LOG.info("Relatório normalizado salvo em %s", out_path)

# ------------------------
# Criação de issues no GitHub (opcional)
# ------------------------
class IssueCreator:
    def __init__(self, config: AgentConfig):
        self.config = config
        # Ajuste: aceita GITHUB_TOKEN do ambiente OU do config.yaml
        token_env = os.getenv("GITHUB_TOKEN")
        token_cfg = (config.github or {}).get("token")
        self.token = token_env or token_cfg
        if not self.token:
            LOG.warning("Nenhum GITHUB_TOKEN fornecido — issues NÃO serão criadas.")
        self.owner = (config.github or {}).get("owner")
        self.repo = (config.github or {}).get("repo")

    def create_issue(self, title: str, body: str, labels: List[str] = []):
        if not self.token or not self.owner or not self.repo:
            LOG.warning("Credenciais GitHub/owner/repo não configuradas. Pulando criação de issue.")
            return None
        url = f"https://api.github.com/repos/{self.owner}/{self.repo}/issues"
        headers = {"Authorization": f"token {self.token}", "Accept": "application/vnd.github.v3+json"}
        payload = {"title": title, "body": body, "labels": labels}
        try:
            r = requests.post(url, json=payload, headers=headers, timeout=15)
            if r.status_code in (200, 201):
                LOG.info("Issue criada no GitHub: %s", r.json().get("html_url"))
                return r.json()
            else:
                LOG.error("Falha ao criar issue no GitHub: %s %s", r.status_code, r.text)
                return None
        except Exception as e:
            LOG.error("Erro ao falar com GitHub: %s", e)
            return None

# ------------------------
# Orquestrador / Pipeline
# ------------------------
class Orchestrator:
    def __init__(self, config: AgentConfig):
        self.config = config
        self.zap = ZAPRunner(config)
        self.afl = AFLRunner(config)
        self.burp = BurpRunner(config)
        self.gen = PayloadGenerator(config)
        self.triage = Triage(config)
        self.issues = IssueCreator(config)

    def run_zap_for_all(self):
        results = []
        for t in self.config.target_urls:
            if t in self.config.off_limits:
                LOG.info("Pulando target off-limits: %s", t)
                continue
            res = self.zap.baseline_scan(target=t)
            if res and res.get("json"):
                # mesmo que res venha com json path, parser precisa manipular se o arquivo existir
                json_path = res.get("json")
                alerts = self.zap.parse_zap_json(json_path)
                results.extend(alerts)
        return results

    def run_fuzz_for_binary(self, binary_path: str, seed_contents: Dict[str, bytes], timeout: int = 60):
        seeds_dir = self.afl.prepare_seeds("seeds", seed_contents)
        return self.afl.run_fuzz([binary_path, "@@"], seeds_dir, timeout=timeout)

    def generate_payloads(self, n: int = 50):
        return self.gen.generate(n=n)

    def triage_and_create_issues(self, raw_alerts: List[Dict[str, Any]]):
        normalized = self.triage.normalize_alerts(raw_alerts)
        rep_path = Path(self.config.reports_dir) / f"normalized_{int(time.time())}.json"
        self.triage.save_report(normalized, str(rep_path))
        for a in normalized:
            if a["score"] >= 3:
                title = f"[AUTO] {a['title']} - {a['risk']}"
                body = f"URL: {a.get('url')}\n\nEvidence: {a.get('evidence')}\n\nDescription: {a.get('desc')}\n\nAutomated triage score: {a.get('score')}"
                self.issues.create_issue(title, body, labels=["security", (a.get("risk") or "").lower()])
        return normalized

    def run_pipeline(self):
        checklist(self.config)
        all_alerts = []
        if self.config.zap.get("enabled", True):
            LOG.info("Fase ZAP...")
            zap_alerts = self.run_zap_for_all()
            all_alerts.extend(zap_alerts)
        if self.config.afl.get("enabled", False):
            LOG.info("Fase AFL (se habilitado)...")
            tb = self.config.afl.get("target_binary")
            seeds = self.config.afl.get("seeds", {})
            if tb:
                self.run_fuzz_for_binary(tb, seeds, timeout=self.config.max_runtime_seconds)
            else:
                LOG.warning("AFL target_binary não fornecido no config.")
        if self.config.generator.get("enabled", True):
            LOG.info("Gerando payloads...")
            payloads = self.generate_payloads(n=30)
            # Varredura leve: faz pedidos simples com payloads (parâmetro q)
            for p in payloads:
                for t in self.config.target_urls:
                    if t in self.config.off_limits:
                        continue
                    try:
                        r = requests.get(t, params={"q": p}, timeout=5)
                        if r.status_code >= 500:
                            LOG.warning("Erro servidor em %s com payload (prefixo): %s", t, p[:40])
                            all_alerts.append({"name": "server-error-payload", "risk": "High", "confidence": "High", "instances": [{"uri": t}], "evidence": f"status {r.status_code}", "description": "Payload gerou erro no servidor"})
                    except Exception as e:
                        LOG.debug("Erro na request com payload: %s", e)
        LOG.info("Triage e geração de relatórios...")
        normalized = self.triage_and_create_issues(all_alerts)
        LOG.info("Pipeline finalizado. %d achados normalizados.", len(normalized))
        return normalized

# ------------------------
# CLI / ponto de entrada
# ------------------------
def main():
    parser = argparse.ArgumentParser(description="sec_agent pipeline MVP")
    parser.add_argument("--config", "-c", required=True, help="Caminho para o arquivo YAML de configuração")
    parser.add_argument("action", choices=["checklist", "zap_scan", "fuzz_run", "generate_payloads", "run_pipeline"], help="Ação a executar")
    parser.add_argument("--target", help="URL alvo ou caminho do binário (dependendo da ação)")
    args = parser.parse_args()

    config = AgentConfig.load(args.config)
    orch = Orchestrator(config)

    if args.action == "checklist":
        checklist(config)
    elif args.action == "zap_scan":
        if not args.target:
            LOG.error("zap_scan requer --target URL")
            sys.exit(2)
        # chamamos baseline_scan e em seguida parse caso tenha sido gerado JSON
        res = orch.zap.baseline_scan(args.target)
        if res and res.get("json"):
            alerts = orch.zap.parse_zap_json(res["json"])
            LOG.info("Alerts extraídos: %d", len(alerts))
            # salvar normalizado localmente
            tri = Triage(config)
            norm = tri.normalize_alerts(alerts)
            out = Path(config.reports_dir) / f"normalized_manual_{int(time.time())}.json"
            tri.save_report(norm, str(out))
            LOG.info("Relatório normalizado salvo em %s", out)
    elif args.action == "fuzz_run":
        tb = config.afl.get("target_binary")
        seeds = config.afl.get("seeds", {})
        if not tb:
            LOG.error("Nenhum afl.target_binary no config.")
            sys.exit(2)
        orch.run_fuzz_for_binary(tb, seeds)
    elif args.action == "generate_payloads":
        payloads = orch.generate_payloads(n=50)
        for p in payloads:
            print(p)
    elif args.action == "run_pipeline":
        orch.run_pipeline()
    else:
        parser.print_help()

if __name__ == "__main__":
    main()
