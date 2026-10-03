"""Validação de entrada para os comandos de reconhecimento."""
import ipaddress
import re

_HOSTNAME_RE = re.compile(
    r"^(?!-)[A-Za-z0-9-]{1,63}(?<!-)(\.(?!-)[A-Za-z0-9-]{1,63}(?<!-))*$"
)


def is_valid_ip(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False


def is_valid_hostname(value: str) -> bool:
    if not value or len(value) > 253 or value.startswith("-"):
        return False
    return bool(_HOSTNAME_RE.match(value))


def is_valid_target(value: str) -> bool:
    """Aceita IP ou hostname/domínio, rejeita qualquer coisa que pareça
    uma flag de linha de comando ou contenha metacaracteres de shell."""
    if not value:
        return False
    if any(ch in value for ch in [" ", "|", "&", ";", "$", "`", "(", ")", "<", ">", "\\", "'", '"']):
        return False
    return is_valid_ip(value) or is_valid_hostname(value)
