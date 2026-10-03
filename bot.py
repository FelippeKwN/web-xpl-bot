# bot do telegram com os comandos de reconhecimento
# cada comando valida o argumento, chama a funcao do recon.py e manda o
# resultado formatado. se der erro esperado (ReconError) manda mensagem
# de erro em vez de quebrar

import html
import logging
import os

from dotenv import load_dotenv
from telegram import Update
from telegram.constants import ParseMode
from telegram.ext import Application, CommandHandler, ContextTypes

from ctf import solve_sqli_lab
from recon import ReconError, is_valid_ip, is_valid_target, run_crt, run_dns, run_gau, run_ipinfo, run_nmap

load_dotenv()

logging.basicConfig(format="%(asctime)s - %(levelname)s - %(message)s", level=logging.INFO)
logger = logging.getLogger(__name__)

IPINFO_TOKEN = os.getenv("IPINFO_TOKEN")
MAX_MSG_LEN = 3800  # telegram limita mensagem em 4096 caracteres

AVISO = "⚠️ Use apenas em hosts/dominios que voce tem autorizacao pra testar.\n"


def formata(titulo, texto):
    texto = html.escape(texto)
    if len(texto) > MAX_MSG_LEN:
        texto = texto[:MAX_MSG_LEN] + "\n... (cortado, saida muito grande)"
    return f"<b>{titulo}</b>\n<pre>{texto}</pre>"


async def start(update, context):
    msg = (
        "🤖 Web XPL Bot - comandos de reconhecimento pra pentest web\n\n"
        "/nmap <host> - scan de portas\n"
        "/gau <dominio> - urls indexadas (passivo)\n"
        "/crt <dominio> - subdominios via certificado (crt.sh)\n"
        "/ipinfo <ip> - geolocalizacao do ip\n"
        "/dns <dominio> - registros dns (bonus)\n"
        "/psqli <url_do_lab> - resolve lab de sqli do portswigger (bonus)\n\n"
        + AVISO
    )
    await update.message.reply_text(msg)


async def nmap_cmd(update, context):
    if not context.args:
        await update.message.reply_text("manda o host, ex: /nmap scanme.nmap.org")
        return
    host = context.args[0]

    if not is_valid_target(host):
        await update.message.reply_text("❌ host invalido")
        return

    await update.message.reply_text(f"escaneando {host}, pode demorar um pouco...")
    try:
        saida = run_nmap(host)
    except ReconError as e:
        await update.message.reply_text(f"❌ {e}")
        return

    await update.message.reply_text(formata(f"nmap - {host}", saida), parse_mode=ParseMode.HTML)


async def gau_cmd(update, context):
    if not context.args:
        await update.message.reply_text("manda o dominio, ex: /gau example.com")
        return
    dominio = context.args[0]

    if not is_valid_target(dominio):
        await update.message.reply_text("❌ dominio invalido")
        return

    await update.message.reply_text(f"procurando urls indexadas pra {dominio}...")
    try:
        saida = run_gau(dominio)
    except ReconError as e:
        await update.message.reply_text(f"❌ {e}")
        return

    await update.message.reply_text(formata(f"gau - {dominio}", saida), parse_mode=ParseMode.HTML)


async def crt_cmd(update, context):
    if not context.args:
        await update.message.reply_text("manda o dominio, ex: /crt example.com")
        return
    dominio = context.args[0]

    if not is_valid_target(dominio):
        await update.message.reply_text("❌ dominio invalido")
        return

    try:
        saida = run_crt(dominio)
    except ReconError as e:
        await update.message.reply_text(f"❌ {e}")
        return

    await update.message.reply_text(formata(f"crt.sh - {dominio}", saida), parse_mode=ParseMode.HTML)


async def ipinfo_cmd(update, context):
    if not context.args:
        await update.message.reply_text("manda o ip, ex: /ipinfo 8.8.8.8")
        return
    ip = context.args[0]

    if not is_valid_ip(ip):
        await update.message.reply_text("❌ ip invalido")
        return

    try:
        saida = run_ipinfo(ip, IPINFO_TOKEN)
    except ReconError as e:
        await update.message.reply_text(f"❌ {e}")
        return

    await update.message.reply_text(formata(f"ipinfo - {ip}", saida), parse_mode=ParseMode.HTML)


async def dns_cmd(update, context):
    if not context.args:
        await update.message.reply_text("manda o dominio, ex: /dns example.com")
        return
    dominio = context.args[0]

    if not is_valid_target(dominio):
        await update.message.reply_text("❌ dominio invalido")
        return

    try:
        saida = run_dns(dominio)
    except ReconError as e:
        await update.message.reply_text(f"❌ {e}")
        return

    await update.message.reply_text(formata(f"dns - {dominio}", saida), parse_mode=ParseMode.HTML)


async def psqli_cmd(update, context):
    if not context.args:
        await update.message.reply_text("manda a url da sua instancia do lab, ex: /psqli https://SEULAB.web-security-academy.net")
        return
    url = context.args[0]

    if not url.startswith("https://"):
        await update.message.reply_text("❌ manda a url completa (com https://)")
        return

    await update.message.reply_text("testando o payload de sql injection...")
    try:
        saida = solve_sqli_lab(url)
    except ReconError as e:
        await update.message.reply_text(f"❌ {e}")
        return

    await update.message.reply_text(formata("psqli - portswigger lab", saida), parse_mode=ParseMode.HTML)


async def erro_handler(update, context):
    logger.error("erro nao tratado: %s", context.error, exc_info=context.error)
    if isinstance(update, Update) and update.message:
        await update.message.reply_text("❌ deu algum erro inesperado aqui, tenta de novo")


def main():
    token = os.getenv("TELEGRAM_BOT_TOKEN")
    if not token:
        print("faltou TELEGRAM_BOT_TOKEN no .env")
        return

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

    logger.info("bot iniciado")
    app.run_polling(allowed_updates=Update.ALL_TYPES)


if __name__ == "__main__":
    main()
