import os
import logging
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
import asyncio

# --- Configuration (IMPORTANT: Use Environment Variables for Production) ---
TOKEN = os.environ.get("TOKEN", "7650332712:AAFWYj8kmLY_eLuiPzXiiUQWyMj8axyuXkY")
GKEY = os.environ.get("GKEY", "AIzaSyBNAp4clDaP7ZJWBpPU1KNozkb5d3yzm38")
VT_API_KEY = os.environ.get("VT_API_KEY", "09dcff205dbe6d5a866976e0a2cb961e6b8476030179ff64bb5cf59e2464f0c5")

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')

# --- Initialize Flask App and python-telegram-bot Application GLOBALLY ---
app = Flask(__name__) # Flask app initialized directly
application = ApplicationBuilder().token(TOKEN).concurrent_updates(True).build()

# NEW: Flag to ensure PTB Application initialization happens only once
bot_initialized = False

# --- Helper functions ---
def check_google_safeBrowse(url):
    endpoint = "https://safeBrowse.googleapis.com/v4/threatMatches:find"
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
        return "Phishing or Malware detected by Google Safe Browse."
    return None

def check_virustotal(url):
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
                return f"⚠️ Detected as suspicious by VirusTotal ({malicious} malicious, {suspicious} suspicious)."
    return None

def is_suspicious_pattern(url):
    phishing_keywords = ["login", "secure", "verify", "paypal", "user-auth", "account", "webscr"]
    manual_phishing_sites = [
        "lt.ke/Students-FREE-LAPT0PS",
        # Add more known phishing URLs or domains here
    ]

    for site in manual_phishing_sites:
        if site.lower() in url.lower():
            return True

    return any(keyword in url.lower() for keyword in phishing_keywords)

# --- Handlers ---
async def start(update: Update, context: ContextTypes.DEFAULT_TYPE):
    await update.message.reply_text("Send me a URL and I’ll check if it's phishing or dangerous.")

async def check_url(update: Update, context: ContextTypes.DEFAULT_TYPE):
    url = update.message.text.strip()
    response_msgs = []

    if not (url.startswith("http://") or url.startswith("https://")):
        await update.message.reply_text("Please send a valid URL starting with http or https.")
        return

    flagged = False

    gsb_result = check_google_safeBrowse(url)
    if gsb_result:
        response_msgs.append("❌ " + gsb_result)
        flagged = True

    vt_result = check_virustotal(url)
    if vt_result:
        response_msgs.append(vt_result)
        flagged = True

    if is_suspicious_pattern(url):
        response_msgs.append("⚠️ URL contains suspicious patterns.")

    if not response_msgs:
        response_msgs.append("✅ Safe: No threats detected.")

    buttons = [
        [InlineKeyboardButton("Recheck", callback_data=url)],
        [InlineKeyboardButton("Bot Info", callback_data="info")],
        [InlineKeyboardButton("Report False Result", url="https://safeBrowse.google.com/safeBrowse/report_phish/")]
    ]
    reply_markup = InlineKeyboardMarkup(buttons)
    await update.message.reply_text("\n".join(response_msgs), reply_markup=reply_markup)

async def button_handler(update: Update, context: ContextTypes.DEFAULT_TYPE):
    query = update.callback_query
    data = query.data
    await query.answer()

    if data.startswith("http"):
        temp_update = Update({'update_id': update.update_id, 'message': query.message, 'callback_query': query})
        temp_update.message.text = data
        await check_url(temp_update, context)
    elif data == "info":
        await query.edit_message_text("PhishCheck Bot - Version 2.0\nNow powered by Google Safe Browse + VirusTotal")

# --- Add Handlers to the Application Object ---
application.add_handler(CommandHandler("start", start))
application.add_handler(MessageHandler(filters.TEXT & ~filters.COMMAND, check_url))
application.add_handler(CallbackQueryHandler(button_handler))

# --- Flask Routes ---
@app.route(f"/{TOKEN}", methods=['POST'])
async def telegram_webhook():
    global bot_initialized # Declare global to modify the flag

    # NEW: Initialize PTB Application on the first request, if not already
    if not bot_initialized:
        logging.info("First webhook received. Initializing python-telegram-bot Application.")
        try:
            await application.initialize()
            await application.start() # Start it as well to be fully ready
            bot_initialized = True
            logging.info("PTB Application initialized and started successfully.")
        except Exception as e:
            logging.error(f"FATAL ERROR during first-request PTB initialization: {e}")
            return "error", 500 # Return error if initialization fails

    if request.method == "POST":
        try:
            update = Update.de_json(request.get_json(force=True), application.bot)
            await application.process_update(update)
            return "ok"
        except Exception as e:
            logging.error(f"Error processing Telegram webhook update (after init): {e}")
            return "error", 500
    return "Method Not Allowed", 405

@app.route("/")
def index():
    return "PhishCheck Bot is up."

@app.route("/uptime", methods=['GET','HEAD'])
def uptime():
    return "OK", 200

# --- Local Development/Testing Setup ---
if __name__ == "__main__":
    # When running locally, app.run() starts a WSGI dev server.
    # We still need to manually initialize for local testing here.
    logging.info("Running locally. Initializing PTB Application for local debugging.")
    asyncio.run(application.initialize()) # Manual initialize for local run
    asyncio.run(application.start()) # Manual start for local run

    port = int(os.environ.get("PORT", 5000))
    logging.info(f"Starting Flask development server on http://0.0.0.0:{port}")
    app.run(host="0.0.0.0", port=port, debug=True)
    
