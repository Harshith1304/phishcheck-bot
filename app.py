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
import asyncio # Keep asyncio import as process_update is async

# --- Configuration (IMPORTANT: Use Environment Variables for Production) ---
# It's crucial to set these in your Render Dashboard's Environment Variables.
# The second value in os.environ.get is a fallback for local testing ONLY.
# For production, Render will provide the environment variables.
TOKEN = os.environ.get("TOKEN", "7650332712:AAFWYj8kmLY_eLuiPzXiiUQWyMj8axyuXkY")
GKEY = os.environ.get("GKEY", "AIzaSyBNAp4clDaP7ZJWBpPU1KNozkb5d3yzm38")
VT_API_KEY = os.environ.get("VT_API_KEY", "09dcff205dbe6d5a866976e0a2cb961e6b8476030179ff64bb5cf59e2464f0c5")

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')

# --- Initialize Flask App and python-telegram-bot Application GLOBALLY ---
# Flask app is initialized directly
app = Flask(__name__) # Back to 'app' for direct Uvicorn use

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

# --- Add Handlers to the Application Object (Moved outside __main__ block) ---
application.add_handler(CommandHandler("start", start))
application.add_handler(MessageHandler(filters.TEXT & ~filters.COMMAND, check_url))
application.add_handler(CallbackQueryHandler(button_handler))

# --- Flask Routes (Decorators now use 'app' directly) ---
# Telegram Webhook Route
@app.route(f"/{TOKEN}", methods=['POST']) # Use 'app' directly here
async def telegram_webhook():
    if request.method == "POST":
        try:
            update = Update.de_json(request.get_json(force=True), application.bot)
            await application.process_update(update)
            return "ok"
        except Exception as e:
            logging.error(f"Error processing Telegram webhook update: {e}")
            return "error", 500
    return "Method Not Allowed", 405

# Root path for general info
@app.route("/") # Use 'app' directly here
def index():
    return "PhishCheck Bot is up."

# Health Check Route (for UptimeRobot)
@app.route("/uptime", methods=['GET','HEAD']) # Use 'app' directly here
def uptime():
    return "OK", 200

# --- Local Development/Testing Setup (This block only runs when script is executed directly) ---
if __name__ == "__main__":
    # In production (on Render), Uvicorn runs the 'app' directly via Procfile.
    # This block is only for local development testing with Flask's built-in server.
    # Webhook setting (Telegram API call) for live bots should be done manually after deployment.

    port = int(os.environ.get("PORT", 5000)) # Default to 5000 for local Flask dev server
    logging.info(f"Starting Flask development server on http://0.0.0.0:{port}")
    # Run the original Flask app directly for local development
    app.run(host="0.0.0.0", port=port, debug=True) # debug=True for more helpful local errors
    
