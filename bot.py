"""
Web XPL Bot — bot de Telegram com comandos de reconhecimento ativo e
passivo para apoiar pentests web (atividade acadêmica).

AVISO: use apenas contra hosts/domínios para os quais você tem autorização
explícita para testar (ambientes próprios, labs como vAPI/crAPI, ou
instâncias pessoais do PortSwigger Web Academy).
"""
import html
import logging
import os

from dotenv import load_dotenv
from telegram import Update
from telegram.constants import ParseMode
from telegram.ext import Application, CommandHandler, ContextTypes

from ctf import solve_sqli_lab
from recon import ReconError, run_crt, run_dns, run_gau, run_ipinfo, run_nmap
from validators import is_valid_ip, is_valid_target

load_dotenv()

logging.basicConfig(
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    level=logging.INFO,
)
logger = logging.getLogger(__name__)

IPINFO_TOKEN = os.getenv("IPINFO_TOKEN")  # opcional
MAX_MSG_LEN = 3800  # margem abaixo do limite de 4096 do Telegram

AVISO_LEGAL = (
    "⚠️ <b>Use apenas em ativos que você tem autorização para testar.</b>\n"
)


def _formatar_resposta(titulo: str, conteudo: str) -> str:
    corpo = html.escape(conteudo)
    if len(corpo) > MAX_MSG_LEN:
        corpo = corpo[:MAX_MSG_LEN] + "\n... (saída truncada)"
    return f"<b>{titulo}</b>\n<pre>{corpo}</pre>"


async def _exigir_argumento(update: Update, args, nome_param: str) -> str | None:
    if not args:
        await update.message.reply_text(f"Uso: informe {nome_param}. Ex.: /{update.message.text.split()[0][1:]} exemplo")
        return None
    return args[0].strip()


async def start(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    texto = (
        "🤖 <b>Web XPL Bot</b> — comandos de reconhecimento para pentest web\n\n"
        "/nmap &lt;host&gt; — scan básico de portas/serviços\n"
        "/gau &lt;domínio&gt; — coleta passiva de URLs indexadas\n"
        "/crt &lt;domínio&gt; — subdomínios via certificados (crt.sh)\n"
        "/ipinfo &lt;ip&gt; — geolocalização/ASN do IP (ipinfo.io)\n"
        "/dns &lt;domínio&gt; — registros A/AAAA/MX/NS/TXT (bônus)\n"
        "/psqli &lt;url_base_do_lab&gt; — resolve o lab PortSwigger de SQLi (bônus)\n\n"
        + AVISO_LEGAL
    )
    await update.message.reply_text(texto, parse_mode=ParseMode.HTML)


async def nmap_cmd(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    host = await _exigir_argumento(update, context.args, "o host (IP ou domínio)")
    if host is None:
        return
    if not is_valid_target(host):
        await update.message.reply_text("❌ Host inválido. Use um IP ou domínio válido, sem espaços ou caracteres especiais.")
        return

    await update.message.reply_text(f"🔎 Escaneando {host}... (pode levar até {90}s)")
    try:
        saida = run_nmap(host)
    except ReconError as exc:
        await update.message.reply_text(f"❌ {exc}")
        return
    await update.message.reply_text(_formatar_resposta(f"nmap — {host}", saida), parse_mode=ParseMode.HTML)


async def gau_cmd(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    dominio = await _exigir_argumento(update, context.args, "o domínio")
    if dominio is None:
        return
    if not is_valid_target(dominio):
        await update.message.reply_text("❌ Domínio inválido.")
        return

    await update.message.reply_text(f"🔎 Coletando URLs passivas para {dominio}...")
    try:
        saida = run_gau(dominio)
    except ReconError as exc:
        await update.message.reply_text(f"❌ {exc}")
        return
    await update.message.reply_text(_formatar_resposta(f"gau — {dominio}", saida), parse_mode=ParseMode.HTML)


async def crt_cmd(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    dominio = await _exigir_argumento(update, context.args, "o domínio")
    if dominio is None:
        return
    if not is_valid_target(dominio):
        await update.message.reply_text("❌ Domínio inválido.")
        return

    await update.message.reply_text(f"🔎 Consultando crt.sh para {dominio}...")
    try:
        saida = run_crt(dominio)
    except ReconError as exc:
        await update.message.reply_text(f"❌ {exc}")
        return
    await update.message.reply_text(_formatar_resposta(f"crt.sh — {dominio}", saida), parse_mode=ParseMode.HTML)


async def ipinfo_cmd(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    ip = await _exigir_argumento(update, context.args, "o IP")
    if ip is None:
        return
    if not is_valid_ip(ip):
        await update.message.reply_text("❌ IP inválido.")
        return

    try:
        saida = run_ipinfo(ip, token=IPINFO_TOKEN)
    except ReconError as exc:
        await update.message.reply_text(f"❌ {exc}")
        return
    await update.message.reply_text(_formatar_resposta(f"ipinfo — {ip}", saida), parse_mode=ParseMode.HTML)


async def dns_cmd(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    dominio = await _exigir_argumento(update, context.args, "o domínio")
    if dominio is None:
        return
    if not is_valid_target(dominio):
        await update.message.reply_text("❌ Domínio inválido.")
        return

    try:
        saida = run_dns(dominio)
    except ReconError as exc:
        await update.message.reply_text(f"❌ {exc}")
        return
    await update.message.reply_text(_formatar_resposta(f"dns — {dominio}", saida), parse_mode=ParseMode.HTML)


async def psqli_cmd(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    url = await _exigir_argumento(update, context.args, "a URL base da sua instância do lab")
    if url is None:
        return
    if not url.startswith("https://"):
        await update.message.reply_text("❌ Informe a URL completa (https://...) da sua instância do lab.")
        return

    await update.message.reply_text("🔎 Testando payload de SQL injection no lab...")
    try:
        saida = solve_sqli_lab(url)
    except ReconError as exc:
        await update.message.reply_text(f"❌ {exc}")
        return
    await update.message.reply_text(_formatar_resposta("PortSwigger — SQLi lab", saida), parse_mode=ParseMode.HTML)


async def erro_handler(update: object, context: ContextTypes.DEFAULT_TYPE) -> None:
    logger.error("Erro não tratado: %s", context.error, exc_info=context.error)
    if isinstance(update, Update) and update.message:
        await update.message.reply_text("❌ Ocorreu um erro inesperado ao processar o comando.")


def main() -> None:
    token = os.getenv("TELEGRAM_BOT_TOKEN")
    if not token:
        raise SystemExit("Defina TELEGRAM_BOT_TOKEN no .env antes de iniciar o bot.")

    app = Application.builder().token(token).build()

    app.add_handler(CommandHandler("start", start))
    app.add_handler(CommandHandler("help", start))
    app.add_handler(CommandHandler("nmap", nmap_cmd))
    app.add_handler(CommandHandler("gau", gau_cmd))
    app.add_handler(CommandHandler("crt", crt_cmd))
    app.add_handler(CommandHandler("ipinfo", ipinfo_cmd))
    app.add_handler(CommandHandler("dns", dns_cmd))
    app.add_handler(CommandHandler("psqli", psqli_cmd))
    app.add_error_handler(erro_handler)

    logger.info("Bot iniciado, aguardando comandos...")
    app.run_polling(allowed_updates=Update.ALL_TYPES)


if __name__ == "__main__":
    main()
