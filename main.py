import os
import logging
import re
from collections import defaultdict
from dotenv import load_dotenv

from telegram import Update
from telegram.ext import (
    Application,
    CommandHandler,
    MessageHandler,
    filters,
    ContextTypes
)

# Load environment variables
load_dotenv()

TELEGRAM_BOT_TOKEN = os.getenv("TELEGRAM_BOT_TOKEN")
WEBHOOK_URL = os.getenv("WEBHOOK_URL")

# --- SECURITY GUARD MEMORY (Warnings Tracker) ---
# Structure: user_warnings[chat_id][user_id] = warning_count
user_warnings = defaultdict(lambda: defaultdict(int))

# --- Logging Configuration ---
logging.basicConfig(
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    level=logging.INFO
)
logger = logging.getLogger(__name__)

# ------------------------------------------------------------------
# --- 3-LEVEL SECURITY FILTER FUNCTION ---
# ------------------------------------------------------------------
def get_moderation_level(text: str) -> int:
    """मैसेज को स्कैन करके डेंजर लेवल (1, 2, या 3) रिटर्न करता है"""
    if not text:
        return 0
    
    text_lower = text.lower()

    # LEVEL 1: Normal / Mild Slangs (No Action / Allowed)
    # इसमें बेवकूफ, गधा, कुत्ता, उल्लू, हगना, मूतना जैसे हल्के शब्द हैं।
    level1_words = [
        r'\b(bakchod|bakchodd|bakchodi|bevda|bewda|bevdey|bewday|bevakoof|bevkoof|bevkuf|bewakoof|bewkoof|bewkuf)\b',
        r'\b(charsi|fattu|gadha|gadhe|hag|haggu|hagne|hagney|kutta|kutte|kuttey|kutia|kutiya|kuttiya|kutti)\b',
        r'\b(launda|lounde|laundey|maar|maro|marunga|paaji|paji|pesaab|pesab|peshaab|peshab)\b',
        r'\b(pilla|pillay|pille|pilley|pisaab|pisab|suar|tatte|tatti|tatty|ullu|moot|mut|mootne|mutne)\b',
        r'\b(saala|ullu|kamina|abe|ale)\b'
    ]
    
    # LEVEL 2: Medium / Heavy Abuse (3 Warnings then Ban)
    # इसमें गंभीर गालियां और प्राइवेट पार्ट्स से जुड़े अपशब्द हैं।
    level2_words = [
        r'\b(aad|aand|babbe|babbey|bube|bubey|bhadua|bhaduaa|bhadva|bhadvaa|bhadwa|bhadwaa)\b',
        r'\b(chooche|choochi|chuchi|chhod|chod|chodd|chudne|chudney|chudwa|chudwaa|chudwane|chudwaane)\b',
        r'\b(choot|chut|chute|chutia|chutiya|chutiye|chuttad|chutad|dalaal|dalal|dalle|dalley)\b',
        r'\b(gadhalund|gaand|gand|gandu|gandfat|gandfut|gandiya|gandiye|goo|gu|gote|gotey|gotte)\b',
        r'\b(harami|haramjada|haraamjaada|haramzyada|haraamzyaada|haraamjaade|haraamzaade|haraamkhor|haramkhor)\b',
        r'\b(jhat|jhaat|jhaatu|jhatu|landi|landy|laude|laudey|laura|lora|lauda|ling|loda|lode|lund|lulli)\b',
        r'\b(mamme|mammey|mooth|muth|nunni|nunnu|porkistan)\b'
    ]
    
    # LEVEL 3: Unexpected / Extreme Toxic Abuse (Direct Ban)
    # इसमें अत्यधिक आपत्तिजनक, सीधे तौर पर बैन करने वाली गालियां (माँ/बहन की गालियां, रंडी, आदि) हैं।
    level3_words = [
        r'\b(bahenchod|behenchod|bhenchod|bhenchodd|bc|b\.c\.)\b',
        r'\b(bhosada|bhosda|bhosdaa|bhosdike|bhonsdike|bsdk|b\.s\.d\.k)\b',
        r'\b(bhosdiki|bhosdiwala|bhosdiwale|bhosadchodal|bhosadchod)\b',
        r'\b(bur|burr|buurr|buur|laundi|loundi|laundiya|loundiya)\b',
        r'\b(madarchod|madarchodd|madarchood|madarchoot|madarchut|mc|m\.c\.)\b',
        r'\b(pkmkb|raand|rand|randi|randy)\b'
    ]

    # Highest Priority: Level 3 Check
    for pattern in level3_words:
        if re.search(pattern, text_lower):
            return 3
            
    # Then Priority: Level 2 Check
    for pattern in level2_words:
        if re.search(pattern, text_lower):
            return 2
            
    # Lowest Priority: Level 1 Check
    for pattern in level1_words:
        if re.search(pattern, text_lower):
            return 1

    return 0

# ------------------------------------------------------------------
# --- MESSAGE PROCESSOR & MODERATION ---
# ------------------------------------------------------------------
async def process_message(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    msg = update.effective_message
    if not msg:
        return
    
    text = msg.text or msg.caption
    if not text:
        return

    chat_id = update.effective_chat.id
    user = update.effective_user
    
    # Ignore bots and empty users
    if not user or user.is_bot:
        return
    
    user_id = user.id
    username = f"@{user.username}" if user.username else user.first_name

    # 1. ADMIN CHECK (Admins & Owners Are Immune)
    is_admin = False
    try:
        member = await context.bot.get_chat_member(chat_id=chat_id, user_id=user_id)
        if member.status in ['administrator', 'creator']:
            is_admin = True
    except Exception as e:
        logger.warning(f"Failed to fetch user status: {e}")

    # If admin, let the message pass without checking
    if is_admin:
        return

    # 2. TRIGGER WORD MODERATION LEVELS
    level = get_moderation_level(text)
    
    if level == 3:
        # 🔴 Level 3: Direct Ban Execution
        try:
            await context.bot.delete_message(chat_id=chat_id, message_id=msg.message_id)
            await context.bot.ban_chat_member(chat_id=chat_id, user_id=user_id)
            await context.bot.send_message(
                chat_id=chat_id,
                text=f"🛑 <b>Direct Ban:</b> {username} ने <b>Level 3 (Extreme Toxic)</b> भाषा का इस्तेमाल किया, इन्हें ग्रुप से तुरंत बैन कर दिया गया है।",
                parse_mode='HTML'
            )
        except Exception as e:
            logger.error(f"Level 3 Action Failed: {e}")

    elif level == 2:
        # 🟡 Level 2: 3 Warnings System
        try:
            await context.bot.delete_message(chat_id=chat_id, message_id=msg.message_id)
            
            # Increment Warning
            user_warnings[chat_id][user_id] += 1
            warnings_count = user_warnings[chat_id][user_id]
            
            if warnings_count >= 3:
                # Ban after 3 warnings
                await context.bot.ban_chat_member(chat_id=chat_id, user_id=user_id)
                await context.bot.send_message(
                    chat_id=chat_id,
                    text=f"🛑 <b>Banned:</b> {username} को Level 2 अपशब्दों के लिए 3 बार चेतावनी दी गई थी, नियम तोड़ने पर इन्हें बैन कर दिया गया है।",
                    parse_mode='HTML'
                )
                user_warnings[chat_id][user_id] = 0  # Reset after ban
            else:
                # Issue Warning
                await context.bot.send_message(
                    chat_id=chat_id,
                    text=f"⚠️ {username}, आपको ग्रुप में अभद्र भाषा (Level 2) के लिए चेतावनी दी जाती है। <b>({warnings_count}/3)</b> तीसरी बार में सीधा बैन किया जाएगा।",
                    parse_mode='HTML'
                )
        except Exception as e:
            logger.error(f"Level 2 Action Failed: {e}")
            
    # 🟢 Level 1: (Kuch Nahi)
    # The code will do absolutely nothing if level == 1 or 0.
    # The message passes safely.

# ------------------------------------------------------------------
# --- COMMANDS ---
# ------------------------------------------------------------------
async def start_command(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    text = (
        "🛡️ <b>Security Bot Activated!</b>\n\n"
        "मैं एक स्ट्रिक्ट ग्रुप मॉडरेटर हूँ। \n"
        "• <b>Level 1:</b> छोटे-मोटे अपशब्दों को मैं इग्नोर करूंगा।\n"
        "• <b>Level 2:</b> 3 वार्निंग देकर यूजर को बैन करूंगा।\n"
        "• <b>Level 3:</b> बिना किसी वार्निंग के तुरंत बैन करूंगा।\n\n"
        "<i>मुझे अपने ग्रुप में एडमिन बनाएं और मैं ग्रुप को साफ़-सुथरा रखूंगा!</i>"
    )
    await update.message.reply_text(text, parse_mode='HTML')

# ------------------------------------------------------------------
# --- MAIN EXECUTION WITH WEBHOOK ---
# ------------------------------------------------------------------
def main() -> None:
    if not TELEGRAM_BOT_TOKEN:
        logger.critical("TELEGRAM_BOT_TOKEN is missing in .env file!")
        return
        
    application = Application.builder().token(TELEGRAM_BOT_TOKEN).build()

    # Handlers Registration
    application.add_handler(CommandHandler("start", start_command))
    application.add_handler(MessageHandler((filters.TEXT | filters.CAPTION) & ~filters.COMMAND, process_message))

    # --- WEBHOOK IMPLEMENTATION (WE HOOKING) ---
    if WEBHOOK_URL:
        PORT = int(os.getenv("PORT", "8000"))
        application.run_webhook(
            listen="0.0.0.0",
            port=PORT,
            url_path=TELEGRAM_BOT_TOKEN,
            webhook_url=f"{WEBHOOK_URL}/{TELEGRAM_BOT_TOKEN}"
        )
        logger.info(f"🛡️ Security Bot started with WEBHOOK on port {PORT}")
    else:
        logger.info("🛡️ Security Bot started with POLLING")
        application.run_polling(poll_interval=1)

if __name__ == '__main__':
    main()
