# Web XPL Bot

Bot de Telegram com comandos de reconhecimento ativo e passivo para apoiar
pentests web (atividade acadêmica de Segurança de APIs).

> ⚠️ **Uso ético**: utilize os comandos apenas contra hosts/domínios para os
> quais você tem autorização explícita (ambientes próprios, labs como
> vAPI/crAPI, ou instâncias pessoais do PortSwigger Web Academy).

## Estrutura do projeto

```
telegram-bot/
├── bot.py           # entrypoint: handlers do Telegram, validação de args, formatação de saída
├── recon.py         # lógica de reconhecimento (nmap, gau, crt.sh, ipinfo, dns) e erros
├── ctf.py           # comando bônus: resolve o lab de SQLi do PortSwigger Web Academy
├── validators.py    # validação de host/IP/domínio (evita injeção de comando e abuso)
├── requirements.txt
├── .env.example
└── README.md
```

A lógica de reconhecimento (`recon.py`, `ctf.py`) é independente da camada do
Telegram (`bot.py`), o que permite testar cada função isoladamente via
`python -c "from recon import run_ipinfo; print(run_ipinfo('8.8.8.8'))"`.

## Como rodar localmente

### 1. Pré-requisitos

- Python 3.10+
- [Nmap](https://nmap.org/download.html) instalado e no PATH (necessário só para `/nmap`)
- Opcional: [gau](https://github.com/lc/gau) instalado e no PATH (se ausente, `/gau` usa automaticamente AlienVault OTX e, em seguida, a Wayback Machine como fallback)
- Um token de bot do Telegram, criado com o [@BotFather](https://t.me/BotFather) (`/newbot`)

### 2. Instalação

```bash
cd telegram-bot
python -m venv venv
source venv/bin/activate        # Windows: venv\Scripts\activate
pip install -r requirements.txt
```

### 3. Configuração

```bash
cp .env.example .env
# edite o .env e cole o token recebido do @BotFather em TELEGRAM_BOT_TOKEN
# IPINFO_TOKEN é opcional (aumenta o limite de requisições ao ipinfo.io)
```

### 4. Executar

```bash
python bot.py
```

O bot entra em modo polling e já responde no chat/privado do Telegram onde
foi adicionado.

## Comandos disponíveis

| Comando | Descrição | Exemplo |
|---|---|---|
| `/start` ou `/help` | Lista os comandos disponíveis | `/start` |
| `/nmap <host>` | Scan básico das 100 portas mais comuns + detecção de versão | `/nmap scanme.nmap.org` |
| `/gau <domínio>` | Coleta passiva de URLs já indexadas (gau, ou fallback via OTX/Wayback Machine) | `/gau example.com` |
| `/crt <domínio>` | Lista subdomínios encontrados em certificados via crt.sh | `/crt example.com` |
| `/ipinfo <ip>` | Geolocalização, ASN/organização e timezone do IP via ipinfo.io | `/ipinfo 8.8.8.8` |
| `/dns <domínio>` *(bônus)* | Registros A/AAAA/MX/NS/TXT | `/dns example.com` |
| `/psqli <url_base>` *(bônus)* | Resolve automaticamente o lab PortSwigger "SQL injection... retrieval of hidden data" na sua instância pessoal | `/psqli https://0a1b00xx.web-security-academy.net` |

### Exemplo de uso — `/ipinfo`

```
Usuário: /ipinfo 8.8.8.8
Bot:
ipinfo — 8.8.8.8
ip: 8.8.8.8
hostname: dns.google
city: Mountain View
region: California
country: US
loc: 37.4056,-122.0775
org: AS15169 Google LLC
```

### Exemplo de uso — `/psqli`

1. No PortSwigger Web Academy, abra o lab **"SQL injection vulnerability in
   WHERE clause allowing retrieval of hidden data"** e clique em *Access the
   lab* — você recebe uma URL única, ex.
   `https://0a1b00xx00xx...web-security-academy.net`.
2. No Telegram: `/psqli https://0a1b00xx00xx...web-security-academy.net`
3. O bot envia `category=Gifts' OR 1=1--` ao endpoint `/filter` e compara a
   quantidade de produtos retornados antes/depois, confirmando o bypass e
   reportando o resultado (lab resolvido quando produtos "unreleased"
   aparecem na listagem).

## Tratamento de erros

- **Entrada inválida** (host/domínio/IP malformado ou contendo caracteres de
  shell): o bot rejeita antes de executar qualquer comando (`validators.py`).
- **Host inacessível / timeout**: cada chamada externa (nmap, HTTP) tem
  timeout definido; o bot responde com `❌ <motivo>` em vez de travar.
- **Erros inesperados**: capturados por um `error_handler` global do
  `python-telegram-bot`, evitando que o processo do bot caia.
