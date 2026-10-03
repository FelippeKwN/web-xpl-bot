"""
Funções de reconhecimento ativo e passivo usadas pelos comandos do bot.

Cada função recebe um alvo já validado (ver validators.py) e devolve uma
string formatada pronta para ser enviada no chat. Erros esperados (timeout,
host inacessível, domínio sem resultados, etc.) são sinalizados com
ReconError, que o bot.py captura e converte em mensagem de erro amigável.
"""
import shutil
import socket
import subprocess

import requests

REQUEST_TIMEOUT = 15  # segundos, para chamadas HTTP a serviços externos
NMAP_TIMEOUT = 90      # segundos, scan é mais lento que uma consulta HTTP


class ReconError(Exception):
    """Erro esperado de negócio (host inválido, timeout, API fora, etc.)."""


def run_nmap(host: str) -> str:
    """Scan básico de portas/serviços (top 100 portas, detecção de versão)."""
    if shutil.which("nmap") is None:
        raise ReconError(
            "nmap não está instalado neste servidor. Instale o Nmap e garanta "
            "que o binário está no PATH."
        )

    try:
        result = subprocess.run(
            ["nmap", "-T4", "--top-ports", "100", "-sV", host],
            capture_output=True,
            text=True,
            timeout=NMAP_TIMEOUT,
        )
    except subprocess.TimeoutExpired:
        raise ReconError(f"Scan em '{host}' excedeu {NMAP_TIMEOUT}s e foi abortado.")

    if result.returncode != 0:
        raise ReconError(f"nmap falhou ao escanear '{host}':\n{result.stderr.strip()[:500]}")

    return result.stdout.strip() or "Nenhuma porta aberta encontrada nas 100 mais comuns."


def run_ipinfo(ip: str, token: str | None = None) -> str:
    """Consulta geolocalização/ASN/organização de um IP via ipinfo.io."""
    url = f"https://ipinfo.io/{ip}/json"
    params = {"token": token} if token else {}

    try:
        resp = requests.get(url, params=params, timeout=REQUEST_TIMEOUT)
    except requests.RequestException as exc:
        raise ReconError(f"Falha ao consultar ipinfo.io: {exc}")

    if resp.status_code == 404:
        raise ReconError(f"IP '{ip}' não encontrado/inválido para o ipinfo.io.")
    if not resp.ok:
        raise ReconError(f"ipinfo.io retornou HTTP {resp.status_code}.")

    data = resp.json()
    campos = ["ip", "hostname", "city", "region", "country", "loc", "org", "postal", "timezone"]
    linhas = [f"{campo}: {data.get(campo, '-')}" for campo in campos if campo in data]
    return "\n".join(linhas) if linhas else "Sem dados retornados pelo ipinfo.io."


def run_crt(domain: str) -> str:
    """Consulta certificados emitidos para o domínio via crt.sh para achar subdomínios."""
    url = "https://crt.sh/"
    params = {"q": f"%.{domain}", "output": "json"}

    try:
        resp = requests.get(url, params=params, timeout=REQUEST_TIMEOUT)
    except requests.RequestException as exc:
        raise ReconError(f"Falha ao consultar crt.sh: {exc}")

    if not resp.ok:
        raise ReconError(f"crt.sh retornou HTTP {resp.status_code} (pode estar sobrecarregado).")

    try:
        registros = resp.json()
    except ValueError:
        raise ReconError("crt.sh não retornou JSON válido (tente novamente em alguns segundos).")

    subdominios = set()
    for registro in registros:
        for nome in registro.get("name_value", "").split("\n"):
            nome = nome.strip().lstrip("*.")
            if nome:
                subdominios.add(nome)

    if not subdominios:
        raise ReconError(f"Nenhum certificado encontrado para '{domain}'.")

    listagem = "\n".join(sorted(subdominios)[:50])
    sufixo = "\n... (lista truncada em 50 itens)" if len(subdominios) > 50 else ""
    return f"{len(subdominios)} subdomínio(s) encontrado(s):\n{listagem}{sufixo}"


def run_gau(domain: str) -> str:
    """Coleta passiva de URLs já indexadas para o domínio.

    Usa o binário `gau` se estiver instalado; caso contrário recorre à API
    pública do Wayback Machine (CDX), a mesma fonte usada internamente pelo gau.
    """
    if shutil.which("gau") is not None:
        try:
            result = subprocess.run(
                ["gau", "--subs", domain],
                capture_output=True,
                text=True,
                timeout=60,
            )
        except subprocess.TimeoutExpired:
            raise ReconError("gau excedeu o tempo limite de 60s.")

        if result.returncode != 0:
            raise ReconError(f"gau falhou: {result.stderr.strip()[:500]}")

        urls = [u for u in result.stdout.splitlines() if u.strip()]
    else:
        url = "https://web.archive.org/cdx/search/cdx"
        params = {
            "url": f"*.{domain}/*",
            "output": "json",
            "fl": "original",
            "collapse": "urlkey",
            "limit": "500",
        }
        try:
            resp = requests.get(url, params=params, timeout=REQUEST_TIMEOUT)
        except requests.RequestException as exc:
            raise ReconError(f"Falha ao consultar Wayback Machine (fallback do gau): {exc}")

        if not resp.ok:
            raise ReconError(f"Wayback Machine retornou HTTP {resp.status_code}.")

        try:
            linhas = resp.json()
        except ValueError:
            raise ReconError("Resposta inválida da Wayback Machine.")

        urls = [linha[0] for linha in linhas[1:]] if len(linhas) > 1 else []

    if not urls:
        raise ReconError(f"Nenhuma URL indexada encontrada para '{domain}'.")

    listagem = "\n".join(urls[:50])
    sufixo = f"\n... (+{len(urls) - 50} URLs, lista truncada)" if len(urls) > 50 else ""
    return f"{len(urls)} URL(s) encontrada(s):\n{listagem}{sufixo}"


def run_dns(domain: str) -> str:
    """[Bônus] Resolve registros A/AAAA/MX/NS/TXT de um domínio."""
    linhas = []

    for familia, nome in ((socket.AF_INET, "A"), (socket.AF_INET6, "AAAA")):
        try:
            enderecos = {info[4][0] for info in socket.getaddrinfo(domain, None, familia)}
            if enderecos:
                linhas.append(f"{nome}: {', '.join(sorted(enderecos))}")
        except socket.gaierror:
            pass

    try:
        import dns.resolver  # dnspython

        for tipo in ("MX", "NS", "TXT"):
            try:
                respostas = dns.resolver.resolve(domain, tipo)
                valores = ", ".join(str(r).strip() for r in respostas)
                linhas.append(f"{tipo}: {valores}")
            except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
                continue
    except ImportError:
        linhas.append("(instale 'dnspython' para registros MX/NS/TXT)")

    if not linhas:
        raise ReconError(f"Não foi possível resolver nenhum registro DNS para '{domain}'.")

    return "\n".join(linhas)
