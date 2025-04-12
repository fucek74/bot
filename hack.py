import logging
from telegram import Update
from telegram.ext import Updater, CommandHandler, CallbackContext
import requests
import time
import json
import re
from typing import List

# ===========================
# Configuration
OWNER_ID = 7836468443  # Replace with your Telegram ID
API_KEY = '7566111301:AAH5tuEOowkjDr4yrYBj_2-vqq6d6tmgQyU'  # Consider using environment variables
DEBUG = True

# Setup logging
logging.basicConfig(
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    level=logging.INFO if not DEBUG else logging.DEBUG
)
logger = logging.getLogger(__name__)

# ===========================
# Helper Functions
def is_owner(update: Update) -> bool:
    """Check if user is owner."""
    return update.effective_user.id == OWNER_ID

def validate_ip(ip: str) -> bool:
    """Validate IP address format."""
    pattern = r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$'
    return re.match(pattern, ip) is not None

def validate_url(url: str) -> bool:
    """Validate URL format."""
    pattern = r'^(http|https)://[^\s/$.?#].[^\s]*$'
    return re.match(pattern, url) is not None

# ===========================
# Command Handlers
def start(update: Update, context: CallbackContext) -> None:
    """Send welcome message."""
    disclaimer = "⚠️ NOTE: This bot is for educational purposes only\n"
    update.message.reply_text(disclaimer + "Welcome to X-BOT vFINAL!\nUse /help for commands.")

def help_command(update: Update, context: CallbackContext) -> None:
    """Show help message."""
    help_text = """
Available commands:
/start - Start the bot
/help - Show this message
/vuln <url> - Check for vulnerabilities (educational)
/iptrace <IP> - Trace IP location
/ddos <host> <port> <time> <method> - DDoS simulation (educational)
/userinfo <username> - Basic Telegram user info
"""
    update.message.reply_text(help_text)

# ===========================
# Security Tools (Educational Purposes Only)
def iptrace(update: Update, context: CallbackContext) -> None:
    """Trace IP location."""
    if not context.args:
        update.message.reply_text("Usage: /iptrace <IP>")
        return
    
    ip = context.args[0]
    if not validate_ip(ip):
        update.message.reply_text("Invalid IP format. Example: 8.8.8.8")
        return

    try:
        response = requests.get(f'https://ipinfo.io/{ip}/json', timeout=10)
        response.raise_for_status()
        data = response.json()
        
        info = f"""
IP: {data.get('ip', 'N/A')}
City: {data.get('city', 'N/A')}
Region: {data.get('region', 'N/A')}
Country: {data.get('country', 'N/A')}
Location: {data.get('loc', 'N/A')}
ISP: {data.get('org', 'N/A')}
"""
        update.message.reply_text(info)
    except Exception as e:
        logger.error(f"IP trace error: {e}")
        update.message.reply_text(f"Error tracing IP: {e}")

def vuln(update: Update, context: CallbackContext) -> None:
    """Educational vulnerability scanner."""
    if not context.args:
        update.message.reply_text("Usage: /vuln <target_url>")
        return
    
    target_url = context.args[0]
    if not validate_url(target_url):
        update.message.reply_text("Invalid URL. Include http:// or https://")
        return

    disclaimer = "⚠️ Scanning only allowed with system owner permission\n"
    update.message.reply_text(disclaimer + "Running educational scan...")

    # Educational payloads
    sqli_payloads = [
        "' OR 1=1 --", 
        "' OR 'a'='a"
    ]
    
    xss_payloads = [
        '<script>alert("XSS")</script>'
    ]

    results = {"sqli": [], "xss": []}
    
    # Test with educational payloads
    for payload in sqli_payloads:
        try:
            test_url = f"{target_url}?id={payload}"
            response = requests.get(test_url, timeout=10)
            if "error" in response.text.lower():
                results["sqli"].append(f"Potential issue with: {payload[:15]}...")
        except Exception as e:
            results["sqli"].append(f"Error: {str(e)[:50]}")

    for payload in xss_payloads:
        try:
            test_url = f"{target_url}?q={payload}"
            response = requests.get(test_url, timeout=10)
            if payload in response.text:
                results["xss"].append("Potential XSS detected")
        except Exception as e:
            results["xss"].append(f"Error: {str(e)[:50]}")

    # Format results
    message = "Educational Scan Results:\n"
    message += "\nSQLi Tests:\n" + ("\n".join(results["sqli"]) if results["sqli"] else "No SQLi patterns found"
    message += "\n\nXSS Tests:\n" + ("\n".join(results["xss"]) if results["xss"] else "No XSS patterns found")
    
    update.message.reply_text(message[:4000])  # Telegram message length limit

# ===========================
# DDoS Simulation (Educational Only)
def ddos(update: Update, context: CallbackContext) -> None:
    """Educational DDoS simulation."""
    if not is_owner(update):
        update.message.reply_text("⚠️ Owner access required")
        return
        
    if len(context.args) < 4:
        update.message.reply_text("Usage: /ddos <host> <port> <time> <method>")
        return

    host, port, duration, method = context.args[0], context.args[1], context.args[2], context.args[3].upper()
    
    disclaimer = """
⚠️ WARNING: Educational simulation only
Real DDoS attacks are illegal in most jurisdictions
Penalties may include fines and imprisonment
"""
    update.message.reply_text(disclaimer + f"\nSimulating {method} traffic to {host}:{port} for {duration}s...")
    
    time.sleep(min(int(duration), 10))  # Limit simulation to 10 seconds max
    update.message.reply_text(f"Simulation completed. No actual traffic was sent.")

# ===========================
# Main Bot Setup
def main() -> None:
    """Start the bot."""
    try:
        updater = Updater(
            token=API_KEY,
            use_context=True,
            request_kwargs={
                'read_timeout': 30,
                'connect_timeout': 30
            }
        )
        dp = updater.dispatcher

        # Add command handlers
        handlers = [
            CommandHandler("start", start),
            CommandHandler("help", help_command),
            CommandHandler("iptrace", iptrace),
            CommandHandler("vuln", vuln),
            CommandHandler("ddos", ddos),
            CommandHandler("userinfo", userinfo),
        ]
        
        for handler in handlers:
            dp.add_handler(handler)

        logger.info("Bot is running...")
        updater.start_polling()
        updater.idle()
    except Exception as e:
        logger.critical(f"Bot failed: {e}")
        raise

if __name__ == '__main__':
    main()
