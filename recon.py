# funcoes de reconhecimento usadas pelos comandos do bot (nmap, ipinfo, crt.sh, gau, dns)
# cada uma recebe o alvo ja validado e devolve uma string pra mandar no chat
# se der erro "esperado" (timeout, host invalido, api fora etc) levanta ReconError

import ipaddress
import re
import shutil
import socket
import subprocess

import requests

REQUEST_TIMEOUT = 15  # segundos pra chamadas http
NMAP_TIMEOUT = 90  # nmap demora mais que uma consulta http normal

HOSTNAME_RE = re.compile(r"^(?!-)[A-Za-z0-9-]{1,63}(?<!-)(\.(?!-)[A-Za-z0-9-]{1,63}(?<!-))*$")


class ReconError(Exception):
    pass


def is_valid_ip(value):
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False


def is_valid_target(value):
    # bloqueia espaco e caracteres de shell pra nao dar problema quando vira
    # argumento de comando (ex no nmap) ou injecao de parametro
    if not value:
        return False
    for ch in " |&;$`()<>\\'\"":
        if ch in value:
            return False
    if is_valid_ip(value):
        return True
    if len(value) > 253 or value.startswith("-"):
        return False
    return bool(HOSTNAME_RE.match(value))


def run_nmap(host):
    if shutil.which("nmap") is None:
        raise ReconError("nmap nao esta instalado / nao esta no PATH")

    try:
        result = subprocess.run(
            ["nmap", "-T4", "--top-ports", "100", "-sV", host],
            capture_output=True,
            text=True,
            timeout=NMAP_TIMEOUT,
        )
    except subprocess.TimeoutExpired:
        raise ReconError(f"scan em {host} demorou demais e foi cancelado")

    if result.returncode != 0:
        raise ReconError(f"nmap deu erro: {result.stderr.strip()[:500]}")

    return result.stdout.strip() or "nenhuma porta aberta nas 100 mais comuns"


def run_ipinfo(ip, token=None):
    url = f"https://ipinfo.io/{ip}/json"
    params = {"token": token} if token else {}

    try:
        resp = requests.get(url, params=params, timeout=REQUEST_TIMEOUT)
    except requests.RequestException as exc:
        raise ReconError(f"erro ao chamar ipinfo.io: {exc}")

    if resp.status_code == 404:
        raise ReconError("ip nao encontrado no ipinfo.io")
    if not resp.ok:
        raise ReconError(f"ipinfo.io respondeu HTTP {resp.status_code}")

    data = resp.json()
    campos = ["ip", "hostname", "city", "region", "country", "loc", "org", "postal", "timezone"]
    linhas = []
    for campo in campos:
        if campo in data:
            linhas.append(f"{campo}: {data[campo]}")
    return "\n".join(linhas) if linhas else "sem dados pra esse ip"


def run_crt(domain):
    url = "https://crt.sh/"
    params = {"q": f"%.{domain}", "output": "json"}

    try:
        resp = requests.get(url, params=params, timeout=REQUEST_TIMEOUT)
    except requests.RequestException as exc:
        raise ReconError(f"erro ao chamar crt.sh: {exc}")

    if not resp.ok:
        raise ReconError(f"crt.sh respondeu HTTP {resp.status_code}")

    try:
        registros = resp.json()
    except ValueError:
        raise ReconError("crt.sh nao devolveu um json valido, tenta de novo")

    # junta tudo num set pra nao repetir subdominio
    subdominios = set()
    for registro in registros:
        nomes = registro.get("name_value", "").split("\n")
        for nome in nomes:
            nome = nome.strip()
            if nome.startswith("*."):
                nome = nome[2:]
            if nome:
                subdominios.add(nome)

    if not subdominios:
        raise ReconError("nenhum certificado encontrado pra esse dominio")

    subdominios = sorted(subdominios)
    listagem = "\n".join(subdominios[:50])
    if len(subdominios) > 50:
        listagem += f"\n... (+{len(subdominios) - 50} itens)"
    return f"{len(subdominios)} subdominio(s) encontrado(s):\n{listagem}"


def run_gau(domain):
    # se tiver o binario gau instalado usa ele, senao tenta a api do OTX
    # e por ultimo a wayback machine (a wayback vive meio travando entao
    # deixei ela por ultimo)
    if shutil.which("gau") is not None:
        try:
            result = subprocess.run(["gau", "--subs", domain], capture_output=True, text=True, timeout=60)
        except subprocess.TimeoutExpired:
            raise ReconError("gau demorou mais de 60s")
        if result.returncode != 0:
            raise ReconError(f"gau deu erro: {result.stderr.strip()[:500]}")
        urls = [u for u in result.stdout.splitlines() if u.strip()]
        return _formata_urls(urls)

    # fonte 1: alienvault otx
    urls = []
    try:
        r = requests.get(
            f"https://otx.alienvault.com/api/v1/indicators/domain/{domain}/url_list",
            params={"limit": 500, "page": 1},
            timeout=REQUEST_TIMEOUT,
        )
        if r.ok:
            dados = r.json()
            urls = [item["url"] for item in dados.get("url_list", []) if item.get("url")]
    except Exception:
        pass  # tenta a proxima fonte

    # fonte 2: wayback machine, só se a primeira nao trouxe nada
    if not urls:
        try:
            r = requests.get(
                "https://web.archive.org/cdx/search/cdx",
                params={
                    "url": f"*.{domain}/*",
                    "output": "json",
                    "fl": "original",
                    "collapse": "urlkey",
                    "limit": "500",
                },
                timeout=REQUEST_TIMEOUT,
            )
            if r.ok:
                linhas = r.json()
                urls = [linha[0] for linha in linhas[1:]] if len(linhas) > 1 else []
        except Exception:
            pass

    if not urls:
        raise ReconError("nao achei nenhuma url indexada (otx e wayback falharam/sem resultado)")

    return _formata_urls(urls)


def _formata_urls(urls):
    if not urls:
        raise ReconError("nenhuma url encontrada")
    listagem = "\n".join(urls[:50])
    if len(urls) > 50:
        listagem += f"\n... (+{len(urls) - 50} urls)"
    return f"{len(urls)} url(s) encontrada(s):\n{listagem}"


def run_dns(domain):
    linhas = []

    for familia, nome in [(socket.AF_INET, "A"), (socket.AF_INET6, "AAAA")]:
        try:
            enderecos = set()
            for info in socket.getaddrinfo(domain, None, familia):
                enderecos.add(info[4][0])
            if enderecos:
                linhas.append(nome + ": " + ", ".join(sorted(enderecos)))
        except socket.gaierror:
            pass

    try:
        import dns.resolver
        for tipo in ("MX", "NS", "TXT"):
            try:
                respostas = dns.resolver.resolve(domain, tipo)
                valores = ", ".join(str(r).strip() for r in respostas)
                linhas.append(f"{tipo}: {valores}")
            except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
                pass
    except ImportError:
        linhas.append("(instala o dnspython pra pegar MX/NS/TXT tambem)")

    if not linhas:
        raise ReconError("nao consegui resolver nenhum registro dns pra esse dominio")

    return "\n".join(linhas)
