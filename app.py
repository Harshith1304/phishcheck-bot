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
from asgiref.wsgi import WsgiToAsgi # CRITICAL: Import WsgiToAsgi for Uvicorn compatibility

# --- Configuration (IMPORTANT: Use Environment Variables for Production) ---
TOKEN = os.environ.get("TOKEN", "7650332712:AAFWYj8kmLY_eLuiPzXiiUQWyMj8axyuXkY")
GKEY = os.environ.get("GKEY", "AIzaSyBNAp4clDaP7ZJWBpPU1KNozkb5d3yzm38")
VT_API_KEY = os.environ.get("VT_API_KEY", "09dcff205dbe6d5a866976e0a2cb961e6b8476030179ff64bb5cf59e2464f0c5")

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')

# --- Initialize Flask App and python-telegram-bot Application GLOBALLY ---
# Create the original Flask application instance (this is your actual Flask app)
original_app = Flask(__name__)

# CRITICAL FIX: Wrap the Flask app with WsgiToAsgi to make it ASGI-compatible for Uvicorn
# This 'app' variable is what Uvicorn will run
app = WsgiToAsgi(original_app)

# Initialize the python-telegram-bot Application instance
application = ApplicationBuilder().token(TOKEN).concurrent_updates(True).build()


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


# --- Flask Routes (Decorators must use 'original_app' as that's the Flask instance) ---
@original_app.route(f"/{TOKEN}", methods=['POST']) # Decorate original_app, not the wrapped 'app'
async def telegram_webhook():
    global bot_initialized # Declare global to modify the flag

    # Initialize PTB Application on the first request, if not already
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

@original_app.route("/") # Decorate original_app
def index():
    return "PhishCheck Bot is up."

@original_app.route("/uptime", methods=['GET','HEAD']) # Decorate original_app
def uptime():
    return "OK", 200

# --- Local Development/Testing Setup ---
if __name__ == "__main__":
    # When running locally, original_app.run() starts a WSGI dev server.
    # For local testing, you might still want to manually initialize the PTB Application.
    logging.info("Running locally. Initializing PTB Application for local debugging.")
    asyncio.run(application.initialize()) # Manual initialize for local run
    asyncio.run(application.start()) # Manual start for local run

    port = int(os.environ.get("PORT", 5000))
    logging.info(f"Starting Flask development server on http://0.0.0.0:{port}")
    original_app.run(host="0.0.0.0", port=port, debug=True)
    
