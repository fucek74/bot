import logging
from telegram import Update
from telegram.ext import Updater, CommandHandler, CallbackContext
import requests
import random
import time
import json
import os
import re
import subprocess
import socket

# ===========================
# API KEYS dan Configs
OWNER_ID = 7836468443
API_KEY = '8141283043:AAFnrHbK9ewqn1FBpwcrSXQdJ9yIYs0KVQY'
DEBUG = True

logging.basicConfig(format='%(asctime)s - %(name)s - %(levelname)s - %(message)s', level=logging.INFO)
logger = logging.getLogger(__name__)

# [Semua fungsi command TETAP SAMA dari /start hingga web_shell_detection]
# ... (paste semua fungsi yang ada tanpa perubahan) ...

# ===========================
# Main function (FIXED)
def main():
    try:
        updater = Updater(API_KEY)  # Hapus use_context untuk kompatibilitas
        dp = updater.dispatcher

        # Daftar handler (TANPA PERUBAHAN)
        dp.add_handler(CommandHandler("start", start))
        dp.add_handler(CommandHandler("help", help))
        dp.add_handler(CommandHandler("iptrace", iptrace))
        dp.add_handler(CommandHandler("whois", whois))
        dp.add_handler(CommandHandler("vuln", vuln))
        dp.add_handler(CommandHandler("ddos", ddos))
        dp.add_handler(CommandHandler("shellfinder", shellfinder))
        dp.add_handler(CommandHandler("stealth_logger", stealth_logger))
        dp.add_handler(CommandHandler("auto_dump_sender", auto_dump_sender))
        dp.add_handler(CommandHandler("web_shell_detection", web_shell_detection))
        dp.add_handler(CommandHandler("userinfo", userinfo))

        updater.start_polling()
        updater.idle()
    except Exception as e:
        logger.error(f"Error: {str(e)}")

if __name__ == '__main__':
    main()
