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
import asyncio # Import asyncio for running async operations

# --- Configuration (IMPORTANT: Use Environment Variables for Production) ---
# It's crucial to set these in your Render Dashboard's Environment Variables
# For local testing, you might set them in a .env file or directly, but DO NOT hardcode for deploy
TOKEN = os.environ.get("TOKEN", "7650332712:AAFWYj8kmLY_eLuiPzXiiUQWyMj8axyuXkY") # Fallback for local testing
GKEY = os.environ.get("GKEY", "AIzaSyBNAp4clDaP7ZJWBpPU1KNozkb5d3yzm38") # Fallback for local testing
VT_API_KEY = os.environ.get("VT_API_KEY", "09dcff205dbe6d5a866976e0a2cb961e6b8476030179ff64bb5cf59e2464f0c5") # Fallback for local testing

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')

# --- Initialize Flask App and python-telegram-bot Application GLOBALLY ---
# These are moved outside the __main__ block so Gunicorn loads them correctly.
app = Flask(__name__)
application = ApplicationBuilder().token(TOKEN).concurrent_updates(True).build()

# --- Helper functions ---
# FIX: Renamed check_google_safeBrowse to check_google_safeBrowse for consistency
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

    # FIX: Call the correctly renamed function
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
        # FIX: Corrected URL for consistency, assuming Google Safe Browse API
        [InlineKeyboardButton("Report False Result", url="https://safeBrowse.google.com/safeBrowse/report_phish/")]
    ]
    reply_markup = InlineKeyboardMarkup(buttons)
    await update.message.reply_text("\n".join(response_msgs), reply_markup=reply_markup)

async def button_handler(update: Update, context: ContextTypes.DEFAULT_TYPE):
    query = update.callback_query
    data = query.data
    await query.answer()

    if data.startswith("http"):
        # Create a temporary update object with the URL as message text for re-check
        temp_update = Update({'update_id': update.update_id, 'message': query.message, 'callback_query': query})
        temp_update.message.text = data # Set the message text to the URL for check_url
        await check_url(temp_update, context) # Pass the modified update and original context
    elif data == "info":
        await query.edit_message_text("PhishCheck Bot - Version 2.0\nNow powered by Google Safe Browse + VirusTotal")

# --- Add Handlers to the Application Object (Moved outside __main__ block) ---
application.add_handler(CommandHandler("start", start))
application.add_handler(MessageHandler(filters.TEXT & ~filters.COMMAND, check_url))
application.add_handler(CallbackQueryHandler(button_handler))

# FIX: Add an explicit post-initialization for the Application object
# This ensures it's ready to process updates when Gunicorn starts the Flask app.
# This should happen *after* handlers are added, but before app.run() or Gunicorn starts listening.
asyncio.run(application.post_init())


# --- Flask Routes ---
# Telegram Webhook Route (Modified to process update via application object)
@app.route(f"/{TOKEN}", methods=['POST'])
async def telegram_webhook():
    if request.method == "POST":
        try:
            # Get the update from Telegram
            update = Update.de_json(request.get_json(force=True), application.bot)
            # Process the update using the globally initialized application object
            await application.process_update(update)
            return "ok"
        except Exception as e:
            logging.error(f"Error processing Telegram webhook update: {e}")
            return "error", 500 # Return a 500 error if processing fails
    return "Method Not Allowed", 405 # For other methods if they somehow hit this endpoint

# Root path for general info
@app.route("/")
def index():
    return "PhishCheck Bot is up."

# Health Check Route (for UptimeRobot)
@app.route("/uptime", methods=['GET','HEAD'])
def uptime():
    return "OK", 200

# --- Local Development/Testing Setup (This block only runs when script is executed directly) ---
if __name__ == "__main__":
    # In production (on Render), Gunicorn runs the 'app' instance directly.
    # This block is only for local development testing with Flask's built-in server.

    # It's a good idea to set the webhook once on startup for local testing.
    # Replace with your actual Render URL if testing on Render's deployed webhook.
    # If running locally with ngrok, this should be your ngrok URL.
    # Make sure this matches the URL you set manually via the Telegram API for actual deployments.
    PUBLIC_WEBHOOK_URL = f"https://phishcheck-bot-1.onrender.com/{TOKEN}" # Use your Render URL

    async def set_initial_webhook_for_local():
        logging.info(f"Setting webhook for local testing to: {PUBLIC_WEBHOOK_URL}")
        try:
            await application.bot.set_webhook(url=PUBLIC_WEBHOOK_URL)
            logging.info("Webhook set successfully for local testing.")
        except Exception as e:
            logging.error(f"Error setting webhook for local testing: {e}")

    # Run the webhook setting once on local startup
    asyncio.run(set_initial_webhook_for_local())

    # Start the Flask development server
    port = int(os.environ.get("PORT", 5000)) # Default to 5000 for local Flask dev server
    logging.info(f"Starting Flask development server on http://0.0.0.0:{port}")
    app.run(host="0.0.0.0", port=port)
            
