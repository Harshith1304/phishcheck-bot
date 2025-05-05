import os
import requests
from flask import Flask, request
from telegram import Update, InlineKeyboardButton, InlineKeyboardMarkup
from telegram.ext import (
    ApplicationBuilder,
    CommandHandler,
    MessageHandler,
    CallbackQueryHandler,
    ContextTypes,
    filters
)

# --- ENVIRONMENT VARIABLES ---
TOKEN = "7650332712:AAFWYj8kmLY_eLuiPzXiiUQWyMj8axyuXkY"
GKEY = "AIzaSyBNAp4clDaP7ZJWBpPU1KNozkb5d3yzm38"
VT_API_KEY = "7e3ef9c9df1bbdfbfe943f35547602a96f3df7fe6f270abe947ec5570934f90c"

# --- MANUAL PHISHING SITES LIST ---
manual_phishing_sites = [
    "https://lt.ke/Students-FREE-LAPT0PS"
]

# --- FLASK APP ---
app = Flask(__name__)

# --- HELPER FUNCTIONS ---

def check_google_safebrowsing(url: str) -> str | None:
    endpoint = "https://safebrowsing.googleapis.com/v4/threatMatches:find"
    payload = {
        "client": {
            "clientId": "phishcheck-bot",
            "clientVersion": "1.0"
        },
        "threatInfo": {
            "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING"],
            "platformTypes": ["ANY_PLATFORM"],
            "threatEntryTypes": ["URL"],
            "threatEntries": [{"url": url}]
        }
    }
    params = {"key": GKEY}
    res = requests.post(endpoint, params=params, json=payload)
    if res.status_code == 200 and res.json().get("matches"):
        return "Phishing or Malware detected by Google Safe Browsing."
    return None

def check_virustotal(url: str) -> str | None:
    headers = {"x-apikey": VT_API_KEY}
    scan_url = requests.post("https://www.virustotal.com/api/v3/urls", data={"url": url}, headers=headers)
    if scan_url.status_code == 200:
        result_id = scan_url.json()["data"]["id"]
        analysis = requests.get(f"https://www.virustotal.com/api/v3/analyses/{result_id}", headers=headers)
        if analysis.status_code == 200:
            stats = analysis.json()["data"]["attributes"]["stats"]
            malicious = stats.get("malicious", 0)
            suspicious = stats.get("suspicious", 0)
            if malicious > 0 or suspicious > 0:
                return f"âš ï¸ Detected as suspicious by VirusTotal ({malicious} malicious, {suspicious} suspicious)."
    return None

def is_suspicious_pattern(url: str) -> bool:
    phishing_keywords = ["login", "secure", "verify", "paypal", "user-auth", "account", "webscr"]
    return any(keyword in url.lower() for keyword in phishing_keywords)

def is_manually_flagged(url: str) -> bool:
    return url.strip().lower() in (site.lower() for site in manual_phishing_sites)

# --- HANDLERS ---

async def start(update: Update, context: ContextTypes.DEFAULT_TYPE):
    await update.message.reply_text("Send me a URL and Iâ€™ll check if it's phishing or dangerous.")

async def check_url(update: Update, context: ContextTypes.DEFAULT_TYPE):
    url = update.message.text.strip()
    response_msgs = []

    if not (url.startswith("http://") or url.startswith("https://")):
        await update.message.reply_text("Please send a valid URL starting with http or https.")
        return

    if is_manually_flagged(url):
        response_msgs.append("âŒ Manually flagged as phishing.")
    else:
        gsb_result = check_google_safebrowsing(url)
        if gsb_result:
            response_msgs.append("âŒ " + gsb_result)

        vt_result = check_virustotal(url)
        if vt_result:
            response_msgs.append(vt_result)

        if is_suspicious_pattern(url):
            response_msgs.append("âš ï¸ URL contains suspicious patterns.")

    if not response_msgs:
        response_msgs.append("âœ… Safe: No threats detected.")

    buttons = [
        [InlineKeyboardButton("Recheck", callback_data=url)],
        [InlineKeyboardButton("Bot Info", callback_data="info")],
        [InlineKeyboardButton("Report False Result", url="https://safebrowsing.google.com/safebrowsing/report_phish/")]
    ]
    reply_markup = InlineKeyboardMarkup(buttons)
    await update.message.reply_text("
".join(response_msgs), reply_markup=reply_markup)

async def button_handler(update: Update, context: ContextTypes.DEFAULT_TYPE):
    query = update.callback_query
    data = query.data
    await query.answer()
    if data.startswith("http"):
        fake_update = Update(update.update_id, message=query.message)
        fake_update.message.text = data
        await check_url(fake_update, context)
    elif data == "info":
        await query.edit_message_text("PhishCheck Bot - Version 2.0
Now powered by Google Safe Browsing + VirusTotal")

# --- MAIN ---

async def main():
    app_bot = ApplicationBuilder().token(TOKEN).build()
    app_bot.add_handler(CommandHandler("start", start))
    app_bot.add_handler(MessageHandler(filters.TEXT & (~filters.COMMAND), check_url))
    app_bot.add_handler(CallbackQueryHandler(button_handler))
    await app_bot.start()
    await app_bot.updater.start_webhook(
        listen="0.0.0.0",
        port=10000,
        url_path=TOKEN,
        webhook_url=f"https://phishcheck.onrender.com/{TOKEN}"
    )
    print("PhishCheck bot is up and running.")
    await app_bot.updater.idle()

if __name__ == "__main__":
    import asyncio
    asyncio.run(main())
