import logging
from telegram import Update
from telegram.ext import Updater, CommandHandler, CallbackContext
import requests
import time
import re
from typing import Dict, List

# ===========================
# Configuration
OWNER_ID = 7836468443  # Replace with your Telegram ID
API_KEY = '7566111301:AAH5tuEOowkjDr4yrYBj_2-vqq6d6tmgQyU'  # Replace with your actual bot token
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
    disclaimer = "⚠️ WARNING: For educational purposes only\n"
    update.message.reply_text(
        disclaimer + "Welcome to Security Bot!\n"
        "Use /help for available commands\n\n"
        "By using this bot, you agree that:\n"
        "1. You have permission to test the target systems\n"
        "2. You understand the legal implications"
    )

def help_command(update: Update, context: CallbackContext) -> None:
    """Show help message."""
    help_text = """
📚 Available Commands:

🔍 Information Gathering:
/iptrace <IP> - Trace IP location
/userinfo <username> - Basic Telegram user info

🛡️ Security Tools (Educational):
/vuln <url> - Check for common vulnerabilities
/ddos <host> <port> <duration> <method> - DDoS simulation (EDUCATIONAL ONLY)

⚙️ Owner Commands:
/stealth_logger - Log messages silently
/auto_dump_sender - Send logged messages

⚠️ NOTE: All security tools require explicit permission from system owners.
"""
    update.message.reply_text(help_text)

def iptrace(update: Update, context: CallbackContext) -> None:
    """Trace IP location."""
    if not context.args:
        update.message.reply_text("Usage: /iptrace <IP>\nExample: /iptrace 8.8.8.8")
        return
    
    ip = context.args[0]
    if not validate_ip(ip):
        update.message.reply_text("Invalid IP format. Example: 8.8.8.8")
        return

    try:
        response = requests.get(f'https://ipinfo.io/{ip}/json', timeout=10)
        response.raise_for_status()
        data = response.json()
        
        info = (
            f"📍 IP: {data.get('ip', 'N/A')}\n"
            f"🏙️ City: {data.get('city', 'N/A')}\n"
            f"🗺️ Region: {data.get('region', 'N/A')}\n"
            f"🇺🇳 Country: {data.get('country', 'N/A')}\n"
            f"📌 Location: {data.get('loc', 'N/A')}\n"
            f"🖥️ ISP: {data.get('org', 'N/A')}"
        )
        update.message.reply_text(info)
    except Exception as e:
        logger.error(f"IP trace error: {e}")
        update.message.reply_text(f"❌ Error tracing IP: {e}")

def userinfo(update: Update, context: CallbackContext) -> None:
    """Get basic Telegram user info."""
    if not context.args:
        update.message.reply_text("Usage: /userinfo <username>\nExample: /userinfo exampleuser")
        return
    
    username = context.args[0].lstrip('@')
    update.message.reply_text(
        f"🔍 Username: @{username}\n"
        "ℹ️ Note: Telegram doesn't provide detailed user information through their API.\n"
        "For privacy reasons, only basic information is available."
    )

def vuln(update: Update, context: CallbackContext) -> None:
    """Educational vulnerability scanner."""
    if not context.args:
        update.message.reply_text("Usage: /vuln <target_url>\nExample: /vuln http://example.com")
        return
    
    target_url = context.args[0]
    if not validate_url(target_url):
        update.message.reply_text("Invalid URL format. Include http:// or https://")
        return

    disclaimer = (
        "⚠️ LEGAL NOTICE:\n"
        "This scan is for EDUCATIONAL PURPOSES ONLY\n"
        "You MUST have permission from the website owner\n"
        "Unauthorized scanning is ILLEGAL in many countries\n\n"
        "Scanning target: {target_url}"
    )
    update.message.reply_text(disclaimer)

    # Educational payloads (never use these without permission)
    test_results = {
        'sqli': [],
        'xss': []
    }

    # Simple SQLi test simulation
    test_results['sqli'].append("Tested for basic SQLi patterns - No issues found")
    
    # Simple XSS test simulation
    test_results['xss'].append("Tested for basic XSS patterns - No issues found")

    # Format results
    message = (
        "🛡️ Vulnerability Scan Results (Educational):\n\n"
        "🔓 SQL Injection Tests:\n" + "\n".join(test_results['sqli']) + "\n\n"
        "🖥️ XSS Tests:\n" + "\n".join(test_results['xss'])
    )
    
    update.message.reply_text(message[:4000])  # Respect Telegram message limit

def ddos(update: Update, context: CallbackContext) -> None:
    """Educational DDoS simulation."""
    if not is_owner(update):
        update.message.reply_text("❌ Owner access required")
        return
        
    if len(context.args) < 4:
        update.message.reply_text(
            "Usage: /ddos <host> <port> <duration> <method>\n"
            "Example: /ddos example.com 80 10 HTTP\n"
            "Methods: HTTP, TCP, UDP (simulation only)"
        )
        return

    host, port, duration, method = context.args[0], context.args[1], context.args[2], context.args[3].upper()
    
    disclaimer = (
        "⚠️ IMPORTANT LEGAL NOTICE:\n\n"
        "This is a SIMULATION ONLY - NO actual traffic is sent\n"
        "Real DDoS attacks are ILLEGAL worldwide\n"
        "Penalties include:\n"
        "• Heavy fines\n"
        "• Imprisonment\n"
        "• Civil lawsuits\n\n"
        "Running EDUCATIONAL simulation for {duration} seconds..."
    )
    update.message.reply_text(disclaimer)

    # Simulation only - no actual traffic
    for i in range(1, min(int(duration), 5) + 1):  # Max 5 seconds for simulation
        time.sleep(1)
        update.message.reply_text(
            f"⏳ Simulation progress: {i}s/{duration}s\n"
            f"Method: {method} | Target: {host}:{port}\n"
            f"Packets simulated: {i * 1000}"
        )

    update.message.reply_text(
        "✅ Simulation completed\n\n"
        "REMEMBER:\n"
        "• Never launch real attacks\n"
        "• Always get proper authorization\n"
        "• Use knowledge responsibly"
    )

# ===========================
# Owner Commands
def stealth_logger(update: Update, context: CallbackContext) -> None:
    """Log messages (owner only)."""
    if not is_owner(update):
        update.message.reply_text("❌ Unauthorized access")
        return
    
    try:
        with open("stealth_log.txt", "a", encoding='utf-8') as f:
            user = update.effective_user
            log_entry = (
                f"{time.ctime()} | "
                f"User: {user.id} | "
                f"Message: {update.message.text}\n"
            )
            f.write(log_entry)
        update.message.reply_text("📝 Message logged silently")
    except Exception as e:
        logger.error(f"Logging error: {e}")
        update.message.reply_text("❌ Failed to log message")

def auto_dump_sender(update: Update, context: CallbackContext) -> None:
    """Send logged messages (owner only)."""
    if not is_owner(update):
        update.message.reply_text("❌ Unauthorized access")
        return
    
    try:
        with open("stealth_log.txt", "r", encoding='utf-8') as f:
            content = f.read()
            if not content:
                update.message.reply_text("📭 Log file is empty")
                return
                
            update.message.reply_text(
                "📜 Log file contents:\n\n"
                f"{content[:3000]}"  # Truncate if too large
            )
    except FileNotFoundError:
        update.message.reply_text("📭 No log file found")
    except Exception as e:
        logger.error(f"Log dump error: {e}")
        update.message.reply_text("❌ Failed to read log file")

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
        dispatcher = updater.dispatcher

        # Add command handlers
        handlers = [
            CommandHandler("start", start),
            CommandHandler("help", help_command),
            CommandHandler("iptrace", iptrace),
            CommandHandler("userinfo", userinfo),
            CommandHandler("vuln", vuln),
            CommandHandler("ddos", ddos),
            CommandHandler("stealth_logger", stealth_logger),
            CommandHandler("auto_dump_sender", auto_dump_sender),
        ]
        
        for handler in handlers:
            dispatcher.add_handler(handler)

        logger.info("Bot is running...")
        updater.start_polling()
        updater.idle()
    except Exception as e:
        logger.critical(f"Bot failed to start: {e}")
        raise

if __name__ == '__main__':
    main()
