"""
sec_agent_unified.py - Orquestrador de segurança (unificado)

Funcionalidades:
 - Integra com ZAP desktop via API (spider + ascan + gerar relatório HTML).
 - Se preferir, executa zap-baseline.py dentro de container Docker (opcional).
 - Integra AFL/AFL++ (fuzzer binário) runner simples.
 - Gerador leve de payloads / mutator.
 - Normalização de achados e criação opcional de issues no GitHub.
 - CLI para ações individuais / pipeline.

Uso:
    python3 sec_agent_unified.py --config config.yaml run_pipeline
    python3 sec_agent_unified.py --config config.yaml zap_scan --target http://localhost:5000
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
import random

# ------------------------
# Configuração de logging
# ------------------------
LOG = logging.getLogger("sec_agent_unified")
LOG.setLevel(logging.DEBUG)
ch = logging.StreamHandler(sys.stdout)
ch.setLevel(logging.INFO)
formatter = logging.Formatter("%(asctime)s %(levelname)s %(message)s")
ch.setFormatter(formatter)
LOG.addHandler(ch)
load_dotenv()

# ------------------------
# Helpers subprocess / fs
# ------------------------
def run_cmd(cmd: List[str], check=True, capture_output=False, env=None, cwd=None, timeout=None):
    """
    Executa comando via subprocess e retorna subprocess.CompletedProcess ou dicionário com stdout/stderr.
    Não lança automaticamente se returncode != 0 (tratamento externo).
    """
    LOG.debug("RUN: %s", " ".join(cmd))
    try:
        res = subprocess.run(cmd, check=False, capture_output=True, text=True, env=env, cwd=cwd, timeout=timeout)
        if res.returncode != 0:
            LOG.warning("Comando retornou exit code %s: %s", res.returncode, " ".join(cmd))
            LOG.debug("STDOUT (prefixo): %s", (res.stdout or "")[:200])
            LOG.debug("STDERR (prefixo): %s", (res.stderr or "")[:200])
        if capture_output:
            return {"stdout": res.stdout, "stderr": res.stderr, "returncode": res.returncode}
        return res
    except subprocess.CalledProcessError as exc:
        LOG.error("CalledProcessError: %s", exc)
        raise
    except Exception as e:
        LOG.error("Erro ao executar comando %s: %s", " ".join(cmd), e)
        raise

def ensure_dir(p: Path):
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
    zap: Dict[str, Any] = field(default_factory=lambda: {"enabled": True, "mode": "auto"})  # mode: auto|api|docker
    afl: Dict[str, Any] = field(default_factory=lambda: {"enabled": False})
    burp: Dict[str, Any] = field(default_factory=lambda: {"enabled": False})
    generator: Dict[str, Any] = field(default_factory=lambda: {"enabled": True})
    github: Dict[str, Any] = field(default_factory=dict)
    max_runtime_seconds: int = 3600

    @staticmethod
    def load(path: str):
        with open(path, "r", encoding="utf-8") as f:
            j = yaml.safe_load(f) or {}
        # Normalize keys for safety
        return AgentConfig(**j)

# ------------------------
# ZAP API helpers (for desktop)
# ------------------------
COMMON_ZAP_PORTS = [8080, 8090, 8443, 12345]  # extra default

def try_detect_zap_api(host: str = "127.0.0.1", ports=None, timeout=1):
    ports = ports or COMMON_ZAP_PORTS
    for p in ports:
        try:
            url = f"http://{host}:{p}/JSON/core/view/version/"
            r = requests.get(url, timeout=timeout)
            if r.status_code == 200:
                LOG.info("Detectado ZAP API em %s:%s", host, p)
                return host, p
        except Exception:
            pass
    return None, None

def zap_api_request(host, port, component, method, params=None, apikey=None, timeout=10):
    params = params.copy() if params else {}
    if apikey:
        params['apikey'] = apikey
    url = f"http://{host}:{port}/JSON/{component}/{method}"
    r = requests.get(url, params=params, timeout=timeout)
    r.raise_for_status()
    return r.json()

def zap_api_post(host, port, component, action, data=None, apikey=None, timeout=20):
    data = data.copy() if data else {}
    if apikey:
        data['apikey'] = apikey
    url = f"http://{host}:{port}/JSON/{component}/{action}"
    r = requests.post(url, data=data, timeout=timeout)
    r.raise_for_status()
    return r.json()

def get_html_report_via_api(host, port, apikey=None, timeout=30):
    url = f"http://{host}:{port}/OTHER/core/other/htmlreport/"
    params = {}
    if apikey:
        params['apikey'] = apikey
    r = requests.get(url, params=params, timeout=timeout)
    r.raise_for_status()
    return r.text

# ------------------------
# Runner ZAP (api + docker fallback)
# ------------------------
class ZAPRunner:
    def __init__(self, config: AgentConfig):
        self.config = config
        self.reports_dir = Path(config.reports_dir)
        ensure_dir(self.reports_dir)
        # API detection cache
        self.api_host = None
        self.api_port = None
        self.apikey = os.getenv("ZAP_API_KEY") or (config.zap.get("apikey") if isinstance(config.zap, dict) else None)

    def docker_available(self) -> bool:
        # prefer shutil.which
        if shutil.which("docker"):
            return True
        # fallback call
        try:
            run_cmd(["docker", "--version"], check=False, capture_output=True)
            return True
        except Exception:
            return False

    def detect_api(self):
        # respect config mode
        mode = (self.config.zap or {}).get("mode", "auto")
        if mode == "docker":
            return None, None
        if mode == "api":
            # try configured host/port first
            host = (self.config.zap or {}).get("host", "127.0.0.1")
            port = (self.config.zap or {}).get("port")
            if port:
                try:
                    r = requests.get(f"http://{host}:{port}/JSON/core/view/version/", timeout=1)
                    if r.status_code == 200:
                        LOG.info("ZAP API (explicit) disponivel em %s:%s", host, port)
                        return host, port
                except Exception:
                    LOG.warning("ZAP API nao acessivel em %s:%s", host, port)
            # fallback: detect common ports
            return try_detect_zap_api(host=host)
        # mode == auto
        # if user set host/port try that
        host = (self.config.zap or {}).get("host", "127.0.0.1")
        port = (self.config.zap or {}).get("port")
        if port:
            try:
                r = requests.get(f"http://{host}:{port}/JSON/core/view/version/", timeout=1)
                if r.status_code == 200:
                    LOG.info("ZAP API detectada em %s:%s", host, port)
                    return host, port
            except Exception:
                pass
        return try_detect_zap_api(host=host)

    # --- API mode operations ---
    def run_spider_api(self, host, port, target, ajax=False, timeout=600):
        LOG.info("Iniciando spider via ZAP API para %s", target)
        try:
            if ajax:
                try:
                    zap_api_post(host, port, 'ajaxSpider', 'action/scan', data={'url': target}, apikey=self.apikey)
                    # poll
                    start = time.time()
                    while True:
                        j = zap_api_request(host, port, 'ajaxSpider', 'view/status', apikey=self.apikey)
                        status = j.get('status') or next(iter(j.values()))
                        LOG.debug("ajax spider status: %s", status)
                        if str(status).lower() in ('stopped', 'done', 'complete', '100'):
                            break
                        if time.time() - start > timeout:
                            raise TimeoutError("AJAX spider timeout")
                        time.sleep(2)
                    LOG.info("AJAX Spider finalizado.")
                    return True
                except Exception as e:
                    LOG.warning("AJAX spider falhou ou indisponivel: %s. Caindo para classic spider.", e)
            # classic spider
            r = zap_api_post(host, port, 'spider', 'action/scan', data={'url': target, 'maxChildren': 0}, apikey=self.apikey)
            LOG.debug("spider started: %s", r)
            start = time.time()
            while True:
                j = zap_api_request(host, port, 'spider', 'view/status', apikey=self.apikey)
                # j expected {'status': 'X'}
                status = None
                if isinstance(j, dict):
                    status = j.get('status') or (next(iter(j.values())) if j else None)
                LOG.debug("spider status: %s", status)
                try:
                    if int(str(status)) >= 100:
                        break
                except Exception:
                    if str(status).lower() in ('100', 'done', 'complete'):
                        break
                if time.time() - start > timeout:
                    raise TimeoutError("Spider timeout")
                time.sleep(2)
            LOG.info("Spider via API finalizado.")
            return True
        except Exception as e:
            LOG.error("Erro na spider via API: %s", e)
            return False

    def run_ascan_api(self, host, port, target, timeout=1800):
        LOG.info("Iniciando active scan via ZAP API para %s", target)
        try:
            r = zap_api_post(host, port, 'ascan', 'action/scan', data={'url': target, 'recurse': True}, apikey=self.apikey)
            LOG.debug("ascan started: %s", r)
            start = time.time()
            while True:
                j = zap_api_request(host, port, 'ascan', 'view/status', apikey=self.apikey)
                # ascan returns {'status': 'X'} or {'scanProgress': 'X'}
                status = None
                for k in ('status', 'scanProgress', 'percentage'):
                    if k in j:
                        status = j[k]
                        break
                if status is None:
                    status = next(iter(j.values()))
                LOG.debug("ascan status: %s", status)
                try:
                    if int(str(status)) >= 100:
                        break
                except Exception:
                    if str(status).lower() in ('100', 'done', 'complete'):
                        break
                if time.time() - start > timeout:
                    raise TimeoutError("Active scan timeout")
                time.sleep(5)
            LOG.info("Active scan via API finalizado.")
            return True
        except Exception as e:
            LOG.error("Erro no active scan via API: %s", e)
            return False

    def fetch_alerts_api(self, host, port, baseurl=None, start=0, count=1000):
        LOG.info("Buscando alerts via API")
        params = {'start': start, 'count': count}
        if baseurl:
            params['baseurl'] = baseurl
        j = zap_api_request(host, port, 'core', 'view/alerts', params=params, apikey=self.apikey)
        # alerts often inside first value
        try:
            alerts = next(iter(j.values()))
        except Exception:
            alerts = j
        # normalize to common schema similar to parse_zap_json
        out = []
        for a in alerts:
            uri = ""
            instances = a.get("instances") or []
            if instances and isinstance(instances, list):
                first = instances[0]
                if isinstance(first, dict):
                    uri = first.get("uri") or first.get("url") or ""
                else:
                    uri = str(first)
            out.append({
                "name": a.get("alert") or a.get("name"),
                "risk": a.get("risk") or a.get("riskdesc"),
                "confidence": a.get("confidence"),
                "url": uri,
                "evidence": a.get("evidence"),
                "desc": a.get("description") or a.get("desc")
            })
        LOG.info("Encontrados %d alerts via API", len(out))
        return out

    # --- Docker baseline mode (existing implementation) ---
    def baseline_scan_docker(self, target: str, report_name_prefix: Optional[str] = None, extra_args: List[str] = []):
        if not self.docker_available():
            LOG.error("Docker não disponível; não é possível rodar o container ZAP.")
            return None
        ts = int(time.time())
        if not report_name_prefix:
            report_name_prefix = hashlib.sha1(target.encode()).hexdigest()[:8]
        html_out = self.reports_dir / f"zap_{report_name_prefix}_{ts}.html"
        json_out = self.reports_dir / f"zap_{report_name_prefix}_{ts}.json"
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
        LOG.info("Iniciando ZAP baseline (docker) para %s", target)
        try:
            res = run_cmd(cmd, check=False, capture_output=True, timeout=self.config.max_runtime_seconds)
            if isinstance(res, dict):
                return_code = res.get("returncode")
                LOG.info("ZAP baseline finalizado (returncode=%s). Arquivo JSON: %s", return_code, json_out)
            else:
                return_code = getattr(res, "returncode", None)
                LOG.info("ZAP baseline finalizado (returncode=%s). Arquivo JSON: %s", return_code, json_out)
            return {"html": str(html_out), "json": str(json_out)}
        except Exception as e:
            LOG.error("ZAP baseline (docker) falhou: %s", e)
            return None

    # public method that chooses api or docker
    def baseline_scan(self, target: str, report_name_prefix: Optional[str]=None):
        ts = int(time.time())
        if not report_name_prefix:
            report_name_prefix = hashlib.sha1(target.encode()).hexdigest()[:8]
            html_out =self.reports_dir / f"zap_{report_name_prefix}_{ts}.html"
            json_out = self.reports_dir / f"zap_{report_name_prefix}_{ts}.json"

            if not self.docker_available():
                LOG.error("Docker nao disponivel para baseline")
                return None
            
            host_reports = str(self.reports_dir.resolve())
            cmd = [
                "docker", "run", "--rm",
                "-v", f"{host_reports}:/zap/wrk:rw",
                "ghcr.io/zaproxy/zaproxy:stable",
                "zap-baseline.py",
                "-t", target,
                "-r", f"/zap/wrk/{html_out.name}",
                "-J", f"/zap/wrk/{json_out.name}",
                "-w", f"/zap/wrk/{report_name_prefix}_{ts}_warn.txt",  # <-- warnings sempre salvos
                "--auto"  # <-- não interativo, gera sempre
            ]
            res = run_cmd(cmd, check=False, capture_output=True, timeout=self.config.max_runtime_seconds)

            LOG.info("ZAP baseline finalizado (returncode=%s). JSON esperado: %s", res["returncode"], json_out)

            if not os.path.exists(json_out):
                LOG.warning("JSON ainda nao encontrado, tentando salvar manualmente...")
                with open(self.reports_dir / "zap_stdout.log", "w") as f:
                    f.write(res["stdout"])

                with open(self.reports_dir / "zap_stderr.log", "w") as f:
                    f.write(res["stderr"])
            return {"html": str(html_out), "json": str(json_out)}

    def parse_zap_json(self, json_path: str) -> List[Dict[str, Any]]:
        if not json_path or not os.path.exists(json_path):
            LOG.error("ZAP JSON não encontrado: %s", json_path)
            return []
        try:
            with open(json_path, "r", encoding="utf-8") as f:
                data = json.load(f)
        except Exception as e:
            LOG.error("Falha ao ler JSON do ZAP: %s", e)
            return []
        alerts = []
        sites = data.get("site") or data.get("sites") or []
        if isinstance(sites, dict):
            sites = [sites]
        if sites:
            for site in sites:
                site_alerts = site.get("alerts") or site.get("alert") or []
                for a in site_alerts:
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
        if shutil.which("afl-fuzz"):
            return True
        try:
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
        if not self.afl_available():
            LOG.error("afl-fuzz não disponível; instale AFL/AFL++ ou execute externamente.")
            return None
        out_dir = self.workdir / out_dir_name
        ensure_dir(out_dir)
        log_stdout = out_dir / "afl_stdout.log"
        log_stderr = out_dir / "afl_stderr.log"
        cmd = ["afl-fuzz", "-i", seeds_dir, "-o", str(out_dir)] + ["--"] + target_cmd
        LOG.info("Iniciando afl-fuzz: %s", " ".join(cmd))
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
# Burp stub
# ------------------------
class BurpRunner:
    def __init__(self, config: AgentConfig):
        self.config = config
    def note(self):
        LOG.info("Burp integration is a stub. Follow Burp docs to integrate via REST API.")

# ------------------------
# Payload generator / mutator
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
        risk_map = {"Low": 1, "Medium": 2, "High": 3, "Critical": 4,
                    "low": 1, "medium": 2, "high": 3, "critical": 4,
                    "Informational": 0, "informational": 0}
        for a in alerts:
            raw_risk = a.get("risk") or ""
            score = 1
            try:
                # try direct mapping
                score = risk_map.get(raw_risk, risk_map.get(str(raw_risk).strip().lower(), 1))
            except Exception:
                score = 1
            norm.append({
                "title": a.get("name") or a.get("title"),
                "risk": a.get("risk"),
                "score": score,
                "url": a.get("url") or (a.get("instances") and a.get("instances")[0].get("uri") if a.get("instances") else ""),
                "evidence": a.get("evidence") or a.get("desc"),
                "desc": a.get("desc") or a.get("description")
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
# GitHub issues creator
# ------------------------
class IssueCreator:
    def __init__(self, config: AgentConfig):
        self.config = config
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
# Orchestrator / Pipeline
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
            # If docker baseline produced JSON file, parse it; if API mode returned alerts, use them
            if not res:
                continue
            # If res contains 'alerts' (API mode), extend
            if res.get("alerts"):
                results.extend(res.get("alerts"))
            elif res.get("json"):
                parsed = self.zap.parse_zap_json(res.get("json"))
                results.extend(parsed)
            else:
                # try to find any json files matching prefix in reports_dir for this target
                LOG.debug("Nenhum json direto retornado; verificando arquivos em %s", self.config.reports_dir)
                # naive search: look for zap_*.json created recently
                rpt_dir = Path(self.config.reports_dir)
                cand = sorted(rpt_dir.glob("zap_*.json"), key=lambda p: p.stat().st_mtime, reverse=True)
                if cand:
                    parsed = self.zap.parse_zap_json(str(cand[0]))
                    results.extend(parsed)
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
# CLI / entrypoint
# ------------------------
def main():
    parser = argparse.ArgumentParser(description="sec_agent_unified pipeline")
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
        res = orch.zap.baseline_scan(args.target)
        if res:
            # if API returned alerts directly
            if res.get("alerts"):
                alerts = res.get("alerts")
            elif res.get("json"):
                alerts = orch.zap.parse_zap_json(res["json"])
            else:
                alerts = []
            LOG.info("Alerts extraídos: %d", len(alerts))
            tri = Triage(config)
            norm = tri.normalize_alerts(alerts)
            out = Path(config.reports_dir) / f"normalized_manual_{int(time.time())}.json"
            tri.save_report(norm, str(out))
            LOG.info("Relatório normalizado salvo em %s", out)
        else:
            LOG.error("zap_scan falhou (nenhum resultado).")
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
