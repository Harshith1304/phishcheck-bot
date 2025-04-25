import os
import requests
from flask import Flask, request
from telegram import Bot, Update, InlineKeyboardButton, InlineKeyboardMarkup
from telegram.ext import Dispatcher, CommandHandler, MessageHandler, Filters, CallbackContext

# Your credentials
TOKEN = "7650332712:AAFWYj8kmLY_eLuiPzXiiUQWyMj8axyuXkY"
GKEY = "AIzaSyBNAp4clDaP7ZJWBpPU1KNozkb5d3yzm38"
VT_API_KEY = "18e7a40a926ad5e25d1f6dce6f946f5118d49a217917f5860a3b1c1d3c79f8f3"

# Flask app and bot setup
app = Flask(__name__)
bot = Bot(token=TOKEN)
dispatcher = Dispatcher(bot, None, use_context=True)

# --- Helper Functions ---
def check_google_safebrowsing(url):
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

def check_virustotal(url):
    headers = {"x-apikey": VT_API_KEY}
    scan = requests.post("https://www.virustotal.com/api/v3/urls", data={"url": url}, headers=headers)
    if scan.status_code == 200:
        result_id = scan.json()["data"]["id"]
        analysis = requests.get(f"https://www.virustotal.com/api/v3/analyses/{result_id}", headers=headers)
        if analysis.status_code == 200:
            stats = analysis.json()["data"]["attributes"]["stats"]
            malicious = stats.get("malicious", 0)
            suspicious = stats.get("suspicious", 0)
            if malicious > 0 or suspicious > 0:
                return f"⚠️ VirusTotal detected ({malicious} malicious, {suspicious} suspicious)."
    return None

def is_suspicious_pattern(url):
    keywords = ["login", "secure", "verify", "paypal", "user-auth", "account", "webscr"]
    return any(k in url.lower() for k in keywords)

# --- Handlers ---
def start(update: Update, context: CallbackContext):
    update.message.reply_text("Send me a URL and I’ll check if it's phishing or dangerous.")

def check_url(update: Update, context: CallbackContext):
    url = update.message.text.strip()
    if not (url.startswith("http://") or url.startswith("https://")):
        update.message.reply_text("Please send a valid URL starting with http or https.")
        return

    response_msgs = []
    flagged = False

    gsb = check_google_safebrowsing(url)
    if gsb:
        response_msgs.append("❌ " + gsb)
        flagged = True

    vt = check_virustotal(url)
    if vt:
        response_msgs.append(vt)
        flagged = True

    if is_suspicious_pattern(url):
        response_msgs.append("⚠️ URL contains suspicious patterns.")

    if not response_msgs:
        response_msgs.append("✅ Safe: No threats detected.")

    buttons = [
        [InlineKeyboardButton("Recheck", callback_data=url)],
        [InlineKeyboardButton("Bot Info", callback_data="info")],
        [InlineKeyboardButton("Report", url="https://safebrowsing.google.com/safebrowsing/report_phish/")]
    ]
    reply_markup = InlineKeyboardMarkup(buttons)
    update.message.reply_text("\n".join(response_msgs), reply_markup=reply_markup)

def button_handler(update: Update, context: CallbackContext):
    query = update.callback_query
    query.answer()
    data = query.data

    if data.startswith("http"):
        fake_update = Update(update.update_id, message=query.message)
        fake_update.message.text = data
        check_url(fake_update, context)
    elif data == "info":
        query.edit_message_text("PhishCheck Bot v2.0\nPowered by Google Safe Browsing + VirusTotal")

# --- Telegram Dispatcher Setup ---
dispatcher.add_handler(CommandHandler("start", start))
dispatcher.add_handler(MessageHandler(Filters.text & ~Filters.command, check_url))
dispatcher.add_handler(MessageHandler(Filters.command, start))

# --- Webhook Setup ---
@app.route(f"/{TOKEN}", methods=["POST"])
def webhook():
    update = Update.de_json(request.get_json(force=True), bot)
    dispatcher.process_update(update)
    return "ok"

@app.route("/")
def home():
    return "PhishBot is up!"

# --- Run App ---
if __name__ == "__main__":
    port = int(os.environ.get("PORT", 10000))
    app.run(host="0.0.0.0", port=port)
