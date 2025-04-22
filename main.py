import os
import requests
from flask import Flask, request
from telegram import Bot, Update, InlineKeyboardButton, InlineKeyboardMarkup
from telegram.ext import Dispatcher, CommandHandler, MessageHandler, Filters, CallbackContext

TOKEN = "7650332712:AAFWYj8kmLY_eLuiPzXiiUQWyMj8axyuXkY"
GKEY = "AIzaSyBNAp4clDaP7ZJWBpPU1KNozkb5d3yzm38"
VT_API_KEY = "2fddb47bd43c97cd564cc1fba6c4dc01456bd0a021c317b1e8c4987aaed7248f"

bot = Bot(token=TOKEN)
app = Flask(__name__)

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
    return any(keyword in url.lower() for keyword in phishing_keywords)

def start(update: Update, context: CallbackContext):
    update.message.reply_text("Send me a URL and I’ll check if it's phishing or dangerous.")

def check_url(update: Update, context: CallbackContext):
    url = update.message.text.strip()
    response_msgs = []

    if not (url.startswith("http://") or url.startswith("https://")):
        update.message.reply_text("Please send a valid URL starting with http or https.")
        return

    flagged = False

    gsb_result = check_google_safebrowsing(url)
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
        [InlineKeyboardButton("Report False Result", url="https://safebrowsing.google.com/safebrowsing/report_phish/")]
    ]
    reply_markup = InlineKeyboardMarkup(buttons)
    update.message.reply_text("\n".join(response_msgs), reply_markup=reply_markup)

def button_handler(update: Update, context: CallbackContext):
    query = update.callback_query
    data = query.data
    query.answer()

    if data.startswith("http"):
        fake_update = Update(update.update_id, message=query.message)
        fake_update.message.text = data
        check_url(fake_update, context)
    elif data == "info":
        query.edit_message_text("PhishCheck Bot - Version 2.0\nPowered by Google Safe Browsing + VirusTotal")

@app.route(f"/{TOKEN}", methods=["POST"])
def webhook():
    update = Update.de_json(request.get_json(force=True), bot)
    dp.process_update(update)
    return "ok"

@app.route("/")
def index():
    return "PhishCheck Bot is up."

dp = Dispatcher(bot, None, workers=0)
dp.add_handler(CommandHandler("start", start))
dp.add_handler(MessageHandler(Filters.text & ~Filters.command, check_url))
dp.add_handler(MessageHandler(Filters.command, start))
dp.add_handler(MessageHandler(Filters.callback_query, button_handler))

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8080)
