from flask import Flask, request
from telegram import Update
from telegram.ext import Application, CommandHandler, MessageHandler, filters, ContextTypes
import requests
import logging
import json
import asyncio

# Your API Keys
BOT_TOKEN = "7650332712:AAFWYj8kmLY_eLuiPzXiiUQWyMj8axyuXkY"
APIVOID_API_KEY = "d0c5a77b7f18d04f28ff8d2643c358aa"
GKEY = "AIzaSyD1-fk6M41nVn4r8e-rZLgD47N7f_nMJl0"
VT_API_KEY = "7f6f2bf4c8b45686efba59eab4b5cfa51e6b60b1780f52b94ae4efbd3f633221"

# Hardcoded phishing URLs
MANUAL_PHISHING_URLS = [
    "https://lt.ke/Students-FREE-LAPT0PS"
]

# Logging
logging.basicConfig(format='%(asctime)s - %(name)s - %(levelname)s - %(message)s', level=logging.INFO)

# Initialize Flask and Telegram app
app = Flask(__name__)
application = Application.builder().token(BOT_TOKEN).build()

# --- Phishing Detection Functions ---

def check_apivoid(url):
    endpoint = "https://endpoint.apivoid.com/urlrep/v1/pay-as-you-go/"
    params = {"key": APIVOID_API_KEY, "url": url}
    try:
        response = requests.get(endpoint, params=params)
        data = response.json()
        score = data.get("data", {}).get("report", {}).get("risk_score", -1)
        if score >= 50:
            return f"[APIVoid] ⚠️ Suspicious URL! Risk Score: {score}"
        return f"[APIVoid] ✅ Looks safe. Risk Score: {score}"
    except:
        return "[APIVoid] ❌ Error checking."

def check_virustotal(url):
    vt_url = "https://www.virustotal.com/api/v3/urls"
    try:
        res = requests.post(vt_url, headers={"x-apikey": VT_API_KEY}, data={"url": url})
        scan_id = res.json()["data"]["id"]
        report_url = f"https://www.virustotal.com/api/v3/analyses/{scan_id}"
        report = requests.get(report_url, headers={"x-apikey": VT_API_KEY}).json()
        stats = report.get("data", {}).get("attributes", {}).get("stats", {})
        if stats.get("malicious", 0) > 0:
            return f"[VirusTotal] ⚠️ Malicious by {stats['malicious']} engines."
        return "[VirusTotal] ✅ Clean."
    except:
        return "[VirusTotal] ❌ Error checking."

def check_google_safebrowsing(url):
    endpoint = f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={GKEY}"
    payload = {
        "client": {"clientId": "phishbot", "clientVersion": "1.0"},
        "threatInfo": {
            "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING"],
            "platformTypes": ["ANY_PLATFORM"],
            "threatEntryTypes": ["URL"],
            "threatEntries": [{"url": url}]
        }
    }
    try:
        res = requests.post(endpoint, json=payload)
        if res.json().get("matches"):
            return "[Google Safe Browsing] ⚠️ Threat detected!"
        return "[Google Safe Browsing] ✅ Clean."
    except:
        return "[Google Safe Browsing] ❌ Error checking."

def run_checks(url):
    if url in MANUAL_PHISHING_URLS:
        return "[Manual] ⚠️ This URL is manually flagged as phishing."
    results = [
        check_apivoid(url),
        check_virustotal(url),
        check_google_safebrowsing(url)
    ]
    return "\n".join(results)

# --- Telegram Handlers ---

async def start(update: Update, context: ContextTypes.DEFAULT_TYPE):
    await update.message.reply_text("Welcome! Send a link and I’ll scan it.")

async def help_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    await update.message.reply_text("Just send a link and I’ll check if it’s safe!")

async def handle_message(update: Update, context: ContextTypes.DEFAULT_TYPE):
    text = update.message.text
    if "http" in text or "www" in text:
        result = run_checks(text)
        await update.message.reply_text(result)
    else:
        await update.message.reply_text("Please send a valid URL.")

# --- Flask Webhook Routes ---

@app.route("/", methods=["POST"])
def webhook():
    update = Update.de_json(request.get_json(force=True), application.bot)
    application.update_queue.put_nowait(update)
    return "OK"

@app.route("/", methods=["GET", "HEAD"])
def health_check():
    return "Bot is alive", 200

# --- Register Telegram Handlers ---

application.add_handler(CommandHandler("start", start))
application.add_handler(CommandHandler("help", help_command))
application.add_handler(MessageHandler(filters.TEXT & ~filters.COMMAND, handle_message))

# --- Main Entrypoint ---

if __name__ == "__main__":
    async def main():
        await application.initialize()
        await application.start()
        await application.bot.set_webhook("https://phishcheck-bot-1.onrender.com/")
        app.run(host="0.0.0.0", port=10000)

    asyncio.run(main())
