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
BOT_TOKEN = os.environ.get("7650332712:AAFWYj8kmLY_eLuiPzXiiUQWyMj8axyuXkY")
VT_API_KEY = os.environ.get("a7a7ac9f34f51bbfe41345e5b04bb8b02d32b589e22792d88f2cbdf43ec15e43")
GKEY = os.environ.get("AIzaSyBNAp4clDaP7ZJWBpPU1KNozkb5d3yzm38")

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

