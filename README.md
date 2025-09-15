Perfeito 👌 — **`README.md`** passo-a-passo para você colocar no repositório. Instruções claras para instalar no **Ubuntu Desktop**, configurar dependências, rodar o agente e depurar.

---

````markdown
# sec_agent — MVP Orquestrador de Segurança

Este projeto é um **agente orquestrador de segurança** que integra ferramentas como:

- [OWASP ZAP](https://www.zaproxy.org/) (DAST, via Docker)
- [AFL/AFL++](https://github.com/AFLplusplus/AFLplusplus) (fuzzing binário)
- Burp Suite (stub/documentação de integração)
- Gerador simples de payloads/mutator
- Normalização de achados e issues opcionais no GitHub

---

## 🚀 Instalação no Ubuntu Desktop

### 1. Dependências do sistema
```bash
sudo apt update
sudo apt install -y python3 python3-venv python3-pip git build-essential curl
````

### 2. Instalar Docker

```bash
# remover versões antigas
sudo apt remove -y docker docker.io containerd runc

# instalar pacotes básicos
sudo apt install -y ca-certificates curl gnupg lsb-release

# adicionar chave e repo Docker
sudo install -m 0755 -d /etc/apt/keyrings
curl -fsSL https://download.docker.com/linux/ubuntu/gpg | sudo gpg --dearmor -o /etc/apt/keyrings/docker.gpg
echo \
  "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.gpg] \
  https://download.docker.com/linux/ubuntu $(lsb_release -cs) stable" | \
  sudo tee /etc/apt/sources.list.d/docker.list > /dev/null

# instalar docker engine
sudo apt update
sudo apt install -y docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin

# adicionar usuário ao grupo docker (logout/login necessário)
sudo usermod -aG docker $USER
```

Teste:

```bash
docker run --rm hello-world
```

### 3. Criar virtualenv Python

```bash
python3 -m venv ~/secagent-venv
source ~/secagent-venv/bin/activate
pip install --upgrade pip
pip install pyyaml requests
```

### 4. Clonar e preparar diretórios

```bash
git clone <url-do-seu-repo>
cd <repo>
mkdir -p sec-reports sec-work
echo "Autorizado: [Seu nome/empresa], data: $(date)" > sec-work/authorization.txt
```

---

## 🔧 Configuração

Edite `config_example.yaml` conforme necessário:

```yaml
target_urls:
  - "http://testphp.vulnweb.com/"
off_limits: []

reports_dir: "sec-reports"
workspace_dir: "sec-work"

zap:
  enabled: true

afl:
  enabled: false   # ative se quiser fuzzing binário

burp:
  enabled: false

generator:
  enabled: true

github:
  owner: "seu-usuario"
  repo: "seu-repo"
  token: null       # ou use variável de ambiente GITHUB_TOKEN

max_runtime_seconds: 600
```

---

## ▶️ Uso

### Checklist (pré-scan)

```bash
python sec_agent.py --config config_example.yaml checklist
```

### Scan ZAP (um alvo específico)

```bash
python sec_agent.py --config config_example.yaml zap_scan --target https://testphp.vulnweb.com/
```

### Gerar payloads

```bash
python sec_agent.py --config config_example.yaml generate_payloads
```

### Rodar pipeline completo

```bash
python sec_agent.py --config config_example.yaml run_pipeline
```

Resultados:

* Relatórios do ZAP → `sec-reports/`
* Relatório normalizado JSON → `sec-reports/normalized_<timestamp>.json`
* Payloads → impressos no console
* Issues no GitHub → criadas se `github.*` configurado

---

## 🐛 Debug & Dicas

* Se **Docker** não roda sem sudo → faça `sudo usermod -aG docker $USER` e relogue.
* Se ZAP não grava relatórios → cheque permissões em `sec-reports` ou rode com volume `:rw`.
* Logs ficam no console (`INFO`); use `LOG.setLevel(logging.DEBUG)` no código para mais detalhes.
* Para testar manualmente ZAP baseline:

  ```bash
  docker run --rm -v "$(pwd)/sec-reports:/zap/wrk/" \
    owasp/zap2docker-stable zap-baseline.py \
    -t https://testphp.vulnweb.com/ \
    -r /zap/wrk/test.html -J /zap/wrk/test.json
  ```

---

## 🔬 (Opcional) Fuzzing com AFL++

Instale via apt:

```bash
sudo apt install -y afl++
```

Exemplo de uso no script (precisa de binário instrumentado):

```bash
python sec_agent.py --config config_example.yaml fuzz_run
```

Documentação oficial: [AFL++ GitHub](https://github.com/AFLplusplus/AFLplusplus)

---

## 📌 Próximos Passos

* Ajustar parsing do JSON do ZAP se a versão gerar chaves diferentes.
* Configurar autenticação no ZAP (headers, cookies) se alvo exigir login.
* Melhorar seeds e instrumentação para fuzzing binário com AFL++.
* Criar workflow CI (GitHub Actions) para rodar scans automáticos.

