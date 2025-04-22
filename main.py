import os
import logging
from telegram import Update, InlineKeyboardButton, InlineKeyboardMarkup
from telegram.ext import (
    ApplicationBuilder, CommandHandler, MessageHandler, CallbackQueryHandler,
    ContextTypes, filters
)
import requests

# Enable logging
logging.basicConfig(
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    level=logging.INFO
)
logger = logging.getLogger(__name__)

# Environment variables
BOT_TOKEN = os.environ.get("TOKEN")
VT_API_KEY = os.environ.get("VT_API_KEY")
GKEY = os.environ.get("GKEY")

# /start command
async def start(update: Update, context: ContextTypes.DEFAULT_TYPE):
    keyboard = [
        [InlineKeyboardButton("Check Link", callback_data='check')],
    ]
    reply_markup = InlineKeyboardMarkup(keyboard)
    await update.message.reply_text("Welcome to PhishBot! Send a suspicious link or choose an option below.", reply_markup=reply_markup)

# Button handler
async def button_handler(update: Update, context: ContextTypes.DEFAULT_TYPE):
    query = update.callback_query
    await query.answer()
    if query.data == 'check':
        await query.edit_message_text("Please send the suspicious link you want to check.")

# Handle messages (links)
async def handle_link(update: Update, context: ContextTypes.DEFAULT_TYPE):
    url = update.message.text.strip()
    result = await check_virustotal(url)
    await update.message.reply_text(result)

# VirusTotal API checker
async def check_virustotal(url):
    headers = {
        "x-apikey": VT_API_KEY
    }
    data = {"url": url}
    response = requests.post("https://www.virustotal.com/api/v3/urls", headers=headers, data=data)

    if response.status_code == 200:
        analysis_id = response.json()["data"]["id"]
        analysis_url = f"https://www.virustotal.com/api/v3/analyses/{analysis_id}"
        analysis = requests.get(analysis_url, headers=headers).json()
        stats = analysis["data"]["attributes"]["stats"]
        malicious = stats["malicious"]
        total = sum(stats.values())
        return f"URL: {url}\nMalicious: {malicious}/{total}"
    else:
        return "Failed to analyze the URL."

# Main function
async def main():
    application = ApplicationBuilder().token(BOT_TOKEN).build()
    
    application.add_handler(CommandHandler("start", start))
    application.add_handler(CallbackQueryHandler(button_handler))
    application.add_handler(MessageHandler(filters.TEXT & (~filters.COMMAND), handle_link))

    logger.info("PhishBot is up!")
    await application.run_polling()

if __name__ == "__main__":
    import asyncio
    asyncio.run(main())
