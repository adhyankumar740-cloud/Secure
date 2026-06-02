import os
import logging
import re
import time
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

# ओनर की ID (ताकि रिपोर्ट भेजी जा सके)
try:
    OWNER_ID = int(os.getenv("OWNER_ID", "0"))
except ValueError:
    OWNER_ID = 0

# --- SECURITY GUARD MEMORY ---
user_warnings = defaultdict(lambda: defaultdict(int))

# --- ADMIN CACHE (To prevent API FloodWait limits) ---
# Structure: {chat_id: {'admins': [id1, id2], 'timestamp': time.time()}}
admin_cache = {}

logging.basicConfig(
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    level=logging.INFO
)
logger = logging.getLogger(__name__)

# ------------------------------------------------------------------
# --- ADMIN CACHE CHECKER ---
# ------------------------------------------------------------------
async def check_is_admin(chat_id: int, user_id: int, context: ContextTypes.DEFAULT_TYPE) -> bool:
    """Check if user is admin, using a 10-minute cache to avoid API limits."""
    # ओनर को हमेशा एडमिन माना जाएगा
    if user_id == OWNER_ID:
        return True

    current_time = time.time()
    
    # अगर कैश में एडमिन लिस्ट है और 10 मिनट (600 सेकंड) से पुरानी नहीं है
    if chat_id in admin_cache and (current_time - admin_cache[chat_id]['timestamp']) < 600:
        return user_id in admin_cache[chat_id]['admins']

    # अगर कैश नहीं है या पुराना हो गया है, तो नया फेच करें
    try:
        admins = await context.bot.get_chat_administrators(chat_id)
        admin_ids = [admin.user.id for admin in admins]
        admin_cache[chat_id] = {'admins': admin_ids, 'timestamp': current_time}
        return user_id in admin_ids
    except Exception as e:
        logger.warning(f"Failed to fetch admins for chat {chat_id}: {e}")
        return False

# ------------------------------------------------------------------
# --- OWNER REPORTER ---
# ------------------------------------------------------------------
async def send_owner_report(context: ContextTypes.DEFAULT_TYPE, message: str):
    """ओनर के DM में रिपोर्ट भेजने का फंक्शन"""
    if OWNER_ID != 0:
        try:
            await context.bot.send_message(chat_id=OWNER_ID, text=message, parse_mode='HTML')
        except Exception as e:
            logger.error(f"Failed to send report to owner (Did you start the bot in DM?): {e}")

# ------------------------------------------------------------------
# --- 3-LEVEL SECURITY FILTER FUNCTION ---
# ------------------------------------------------------------------
def get_moderation_level(text: str) -> int:
    if not text:
        return 0
    text_lower = text.lower()

    # --- LEVEL 3: Extreme Toxic Abuse (Direct Ban) ---
    l3_hinglish = r'\b(bahenchod|behenchod|bhenchod|bhenchodd|bc|b\.c\.|bhosada|bhosda|bhosdaa|bhosdike|bhonsdike|bsdk|b\.s\.d\.k|bhosdiki|bhosdiwala|bhosdiwale|bhosadchodal|bhosadchod|bur|burr|buurr|buur|laundi|loundi|laundiya|loundiya|madarchod|madarchodd|madarchood|madarchoot|madarchut|mc|m\.c\.|pkmkb|raand|rand|randi|randy)\b'
    l3_hindi = ['बहनचोद', 'बेहेनचोद', 'भेनचोद', 'भोसड़ा', 'भोसड़ीके', 'भोसड़ीकी', 'भोसड़ीवाला', 'भोसड़ीवाले', 'भोसरचोदल', 'भोसदचोद', 'भोसड़ाचोदल', 'भोसड़ाचोद', 'बुर', 'लौंडी', 'लौंडिया', 'मादरचोद', 'मादरचूत', 'मादरचुत', 'रांड', 'रंडी']

    # --- LEVEL 2: Medium / Heavy Abuse (3 Warnings then Ban) ---
    l2_hinglish = r'\b(aad|aand|babbe|babbey|bube|bubey|bhadua|bhaduaa|bhadva|bhadvaa|bhadwa|bhadwaa|chooche|choochi|chuchi|chhod|chod|chodd|chudne|chudney|chudwa|chudwaa|chudwane|chudwaane|choot|chut|chute|chutia|chutiya|chutiye|chuttad|chutad|dalaal|dalal|dalle|dalley|gadhalund|gaand|gand|gandu|gandfat|gandfut|gandiya|gandiye|goo|gu|gote|gotey|gotte|harami|haramjada|haraamjaada|haramzyada|haraamzyaada|haraamjaade|haraamzaade|haraamkhor|haramkhor|jhat|jhaat|jhaatu|jhatu|landi|landy|laude|laudey|laura|lora|lauda|ling|loda|lode|lund|lulli|mamme|mammey|mooth|muth|nunni|nunnu|porkistan)\b'
    l2_hindi = ['आंड़', 'आंड', 'आँड', 'बब्बे', 'बूबे', 'भड़ुआ', 'भड़वा', 'चूचे', 'चूची', 'चुची', 'चोद', 'चुदने', 'चुदवा', 'चुदवाने', 'चूत', 'चुटिया', 'चूतिये', 'चुत्तड़', 'चूत्तड़', 'दलाल', 'दलले', 'गधालंड', 'गांड', 'गांडू', 'गंडफट', 'गंडिया', 'गंडिये', 'गू', 'गोटे', 'हरामी', 'हरामजादा', 'हरामज़ादा', 'हरामजादे', 'हरामज़ादे', 'हरामखोर', 'झाट', 'झाटू', 'लेंडी', 'लोड़े', 'लौड़े', 'लौड़ा', 'लोड़ा', 'लौडा', 'लिंग', 'लोडा', 'लोडे', 'लंड', 'लुल्ली', 'मम्मे', 'मूठ', 'मुठ', 'नुननी', 'नुननु', 'पोरकिस्तान']

    # --- LEVEL 1: Normal / Mild Slangs (No Action / Allowed) ---
    l1_hinglish = r'\b(bakchod|bakchodd|bakchodi|bevda|bewda|bevdey|bewday|bevakoof|bevkoof|bevkuf|bewakoof|bewkoof|bewkuf|charsi|fattu|gadha|gadhe|hag|haggu|hagne|hagney|kutta|kutte|kuttey|kutia|kutiya|kuttiya|kutti|launda|lounde|laundey|maar|maro|marunga|paaji|paji|pesaab|pesab|peshaab|peshab|pilla|pillay|pille|pilley|pisaab|pisab|suar|tatte|tatti|tatty|ullu|moot|mut|mootne|mutne|saala|kamina|abe|ale)\b'
    l1_hindi = ['बकचोद', 'बकचोदी', 'बेवड़ा', 'बेवड़े', 'बेवकूफ', 'चरसी', 'फट्टू', 'गधा', 'गधे', 'हग', 'हग्गू', 'हगने', 'कुत्ता', 'कुत्ते', 'कुतिया', 'कुत्ती', 'लौंडा', 'लौंडे', 'मार', 'मारो', 'मारूंगा', 'पाजी', 'पेसाब', 'पेशाब', 'पिल्ला', 'पिल्ले', 'पिसाब', 'सुअर', 'सूअर', 'टट्टे', 'टट्टी', 'उल्लू', 'मूत', 'मुत', 'मूतने', 'मुतने', 'साला', 'कमीना', 'अबे']

    # Priority 3 Check (Hinglish + Hindi)
    if re.search(l3_hinglish, text_lower) or any(word in text_lower for word in l3_hindi):
        return 3
    # Priority 2 Check (Hinglish + Hindi)
    if re.search(l2_hinglish, text_lower) or any(word in text_lower for word in l2_hindi):
        return 2
    # Priority 1 Check (Hinglish + Hindi)
    if re.search(l1_hinglish, text_lower) or any(word in text_lower for word in l1_hindi):
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

    chat = update.effective_chat
    user = update.effective_user
    
    if not user or user.is_bot:
        return
    
    user_id = user.id
    username = f"@{user.username}" if user.username else user.first_name

    # 1. ADMIN CHECK (Using Cache)
    is_admin = await check_is_admin(chat.id, user_id, context)
    if is_admin:
        return

    # 2. TRIGGER WORD MODERATION LEVELS
    level = get_moderation_level(text)
    
    if level == 3:
        # 🔴 Level 3: Direct Ban Execution
        try:
            await context.bot.delete_message(chat_id=chat.id, message_id=msg.message_id)
            await context.bot.ban_chat_member(chat_id=chat.id, user_id=user_id)
            
            alert = f"🛑 <b>Direct Ban:</b> {username} ने <b>Level 3 (Extreme Toxic)</b> भाषा का इस्तेमाल किया, इन्हें ग्रुप से तुरंत बैन कर दिया गया है।"
            await context.bot.send_message(chat_id=chat.id, text=alert, parse_mode='HTML')
            
            # Send Report to Owner
            report = f"🚨 <b>SECURITY ALERT (Level 3 Ban)</b>\n<b>Group:</b> {chat.title}\n<b>User:</b> {username} (`{user_id}`)\n<b>Message:</b> {text}"
            await send_owner_report(context, report)

        except Exception as e:
            logger.error(f"Level 3 Action Failed: {e}")

    elif level == 2:
        # 🟡 Level 2: 3 Warnings System
        try:
            await context.bot.delete_message(chat_id=chat.id, message_id=msg.message_id)
            
            user_warnings[chat.id][user_id] += 1
            warnings_count = user_warnings[chat.id][user_id]
            
            if warnings_count >= 3:
                await context.bot.ban_chat_member(chat_id=chat.id, user_id=user_id)
                alert = f"🛑 <b>Banned:</b> {username} को Level 2 अपशब्दों के लिए 3 बार चेतावनी दी गई थी, नियम तोड़ने पर इन्हें बैन कर दिया गया है।"
                await context.bot.send_message(chat_id=chat.id, text=alert, parse_mode='HTML')
                
                report = f"🚨 <b>SECURITY ALERT (Level 2 Max Warnings Ban)</b>\n<b>Group:</b> {chat.title}\n<b>User:</b> {username} (`{user_id}`)"
                await send_owner_report(context, report)
                
                user_warnings[chat.id][user_id] = 0 
            else:
                alert = f"⚠️ {username}, आपको ग्रुप में अभद्र भाषा (Level 2) के लिए चेतावनी दी जाती है। <b>({warnings_count}/3)</b> तीसरी बार में सीधा बैन किया जाएगा।"
                await context.bot.send_message(chat_id=chat.id, text=alert, parse_mode='HTML')
                
                report = f"⚠️ <b>WARNING LOGGED ({warnings_count}/3)</b>\n<b>Group:</b> {chat.title}\n<b>User:</b> {username}\n<b>Message:</b> {text}"
                await send_owner_report(context, report)

        except Exception as e:
            logger.error(f"Level 2 Action Failed: {e}")

# ------------------------------------------------------------------
# --- COMMANDS (Status & Testing) ---
# ------------------------------------------------------------------
async def start_command(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    text = (
        "🛡️ <b>Security Bot Activated!</b>\n\n"
        "मैं एक स्ट्रिक्ट ग्रुप मॉडरेटर हूँ।\n"
        "• <b>Level 1:</b> इग्नोर (हल्के शब्द)\n"
        "• <b>Level 2:</b> 3 वार्निंग फिर बैन\n"
        "• <b>Level 3:</b> डायरेक्ट बैन\n\n"
        "<i>बोट का स्टेटस चेक करने के लिए /status दबाएं। मुझे अपने ग्रुप में एडमिन बनाएं!</i>"
    )
    await update.message.reply_text(text, parse_mode='HTML')

async def status_command(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    """चेक करने के लिए कि बोट एक्टिव है या नहीं"""
    owner_status = "Linked ✅" if OWNER_ID != 0 else "Not Configured ❌ (No Reports will be sent)"
    text = (
        "🟢 <b>Bot Status: ONLINE & ACTIVE</b>\n\n"
        f"👤 <b>Owner ID:</b> {owner_status}\n"
        "🛡️ <b>Security Engine:</b> 3-Level Active\n"
        "⚡ <b>Admin Cache:</b> Optimized"
    )
    await update.message.reply_text(text, parse_mode='HTML')

# ------------------------------------------------------------------
# --- MAIN EXECUTION ---
# ------------------------------------------------------------------
def main() -> None:
    if not TELEGRAM_BOT_TOKEN:
        logger.critical("TELEGRAM_BOT_TOKEN is missing in .env file!")
        return
        
    application = Application.builder().token(TELEGRAM_BOT_TOKEN).build()

    application.add_handler(CommandHandler("start", start_command))
    application.add_handler(CommandHandler(["status", "ping"], status_command))
    application.add_handler(MessageHandler((filters.TEXT | filters.CAPTION) & ~filters.COMMAND, process_message))

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
