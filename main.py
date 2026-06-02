import os
import re
import time
import json
import asyncio
import logging
import unicodedata
import aiosqlite
import telegram
import httpx  # Required for Perspective API and webhook keeping
from collections import defaultdict
from dotenv import load_dotenv

from telegram import (
    Update, 
    ChatPermissions, 
    InlineKeyboardButton, 
    InlineKeyboardMarkup,
    MessageEntity,
    ChatMemberAdministrator,
    ChatMemberOwner
)
from telegram.ext import (
    Application,
    CommandHandler,
    MessageHandler,
    CallbackQueryHandler,
    filters,
    ContextTypes
)
from telegram.constants import ParseMode
from telegram.error import TelegramError
from openai import AsyncOpenAI  # Groq uses OpenAI compatible client

# ------------------------------------------------------------------
# CONFIGURATION & ENVIRONMENT SETUP
# ------------------------------------------------------------------
load_dotenv()
TELEGRAM_BOT_TOKEN = os.getenv("TELEGRAM_BOT_TOKEN")
PERSPECTIVE_API_KEY = os.getenv("PERSPECTIVE_API_KEY")
OWNER_ID = int(os.getenv("OWNER_ID", "0"))

# GROQ SPECIFIC CONFIGURATION
GROQ_API_KEY = os.getenv("GROQ_API_KEY")
GROQ_MODEL = os.getenv("GROQ_MODEL", "llama-3.3-70b-versatile") 

# WEBHOOK CONFIGURATION FOR RENDER
WEBHOOK_URL = os.getenv("WEBHOOK_URL")
PORT = int(os.getenv("PORT", "8000"))

logging.basicConfig(
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    level=logging.INFO
)
logger = logging.getLogger("MaximumSecurityMod")
logging.getLogger("httpx").setLevel(logging.WARNING)

# Base Local Engine Filters
PROFANITY_REGEX = re.compile(r'(bhenchod|madarchod|chutiya|gand|lund|behenchod|randi|sala|kamina|fuck|shit|bitch|asshole)', re.IGNORECASE)
SCAM_KEYWORDS = re.compile(r'(crypto_help|support_desk|air_drop|binance_support|trust_wallet|free_tokens|claim_airdrop)', re.IGNORECASE)
BANNED_EXTENSIONS = {'.exe', '.apk', '.bat', '.scr', '.vbs', '.iso', '.dmg', '.msi', '.sh'}
TRUSTED_DOMAINS = {'youtube.com', 'youtu.be', 'wikipedia.org', 'github.com', 'google.com', 't.me'}

# --- IN-MEMORY CACHES ---
admin_cache = {}
flood_cache = defaultdict(lambda: defaultdict(list))
dup_cache = defaultdict(lambda: defaultdict(list))
media_cache = defaultdict(lambda: defaultdict(list))
join_cache = defaultdict(list)
lockdown_state = defaultdict(bool)
captcha_registry = defaultdict(dict)

# Groq AI SDK Configuration (Using OpenAI wrapper pointed to Groq)
ai_client = AsyncOpenAI(
    api_key=GROQ_API_KEY, 
    base_url="https://api.groq.com/openai/v1"
) if GROQ_API_KEY else None

# ------------------------------------------------------------------
# GOOGLE PERSPECTIVE API (Hinglish/Hindi/English Specialist)
# ------------------------------------------------------------------
async def check_perspective_toxicity(text: str) -> float:
    if not PERSPECTIVE_API_KEY or not text.strip():
        return 0.0
    
    url = f"https://commentanalyzer.googleapis.com/v1alpha1/comments:analyze?key={PERSPECTIVE_API_KEY}"
    payload = {
        "comment": {"text": text},
        "languages": ["en", "hi"],
        "requestedAttributes": {"TOXICITY": {}, "SEVERE_TOXICITY": {}, "INSULT": {}}
    }
    
    async with httpx.AsyncClient() as client:
        try:
            response = await client.post(url, json=payload, timeout=3.0)
            if response.status_code == 200:
                data = response.json()
                scores = [
                    data["attributeScores"]["TOXICITY"]["summaryScore"]["value"],
                    data["attributeScores"]["SEVERE_TOXICITY"]["summaryScore"]["value"],
                    data["attributeScores"]["INSULT"]["summaryScore"]["value"]
                ]
                return max(scores)
        except Exception as e:
            logger.error(f"Perspective API connection issue: {e}")
    return 0.0

# ------------------------------------------------------------------
# COMPATIBILITY LAYER: TELEGRAM PERMISSION WRAPPERS
# ------------------------------------------------------------------
def can_delete_messages(member) -> bool:
    if isinstance(member, ChatMemberOwner): return True
    return bool(getattr(member, 'can_delete_messages', False))

def can_ban_members(member) -> bool:
    if isinstance(member, ChatMemberOwner): return True
    return bool(getattr(member, 'can_ban_users', False) or getattr(member, 'can_restrict_members', False))

# ------------------------------------------------------------------
# LOCAL SQLITE DATABASE LAYER
# ------------------------------------------------------------------
class DatabaseLayer:
    def __init__(self, db_path="max_security_mod.db"):
        self.db_path = db_path

    async def init_db(self):
        async with aiosqlite.connect(self.db_path) as db:
            await db.execute("PRAGMA journal_mode=WAL;")
            await db.execute("PRAGMA synchronous=NORMAL;")
            await db.execute('''CREATE TABLE IF NOT EXISTS warnings (chat_id INTEGER, user_id INTEGER, count INTEGER, PRIMARY KEY(chat_id, user_id))''')
            await db.execute('''CREATE TABLE IF NOT EXISTS mod_logs (id INTEGER PRIMARY KEY AUTOINCREMENT, chat_id INTEGER, user_id INTEGER, admin_id INTEGER, action TEXT, reason TEXT, target_text TEXT, timestamp DATETIME DEFAULT CURRENT_TIMESTAMP)''')
            await db.execute('''CREATE TABLE IF NOT EXISTS whitelist (chat_id INTEGER, user_id INTEGER, PRIMARY KEY(chat_id, user_id))''')
            await db.execute('''CREATE TABLE IF NOT EXISTS lockdown_state (chat_id INTEGER PRIMARY KEY, active INTEGER, reason TEXT, expires_at INTEGER)''')
            await db.execute('''CREATE TABLE IF NOT EXISTS captcha_registry (chat_id INTEGER, user_id INTEGER, message_id INTEGER, expires_at INTEGER, PRIMARY KEY(chat_id, user_id))''')
            await db.execute('''CREATE TABLE IF NOT EXISTS managed_chats (chat_id INTEGER PRIMARY KEY, title TEXT, added_at DATETIME DEFAULT CURRENT_TIMESTAMP)''')
            await db.commit()

    async def register_chat(self, chat_id: int, title: str):
        async with aiosqlite.connect(self.db_path) as db:
            await db.execute('''INSERT INTO managed_chats (chat_id, title) VALUES (?, ?) ON CONFLICT(chat_id) DO UPDATE SET title = excluded.title''', (chat_id, title or "Unknown Chat Group"))
            await db.commit()

    async def persist_lockdown(self, chat_id: int, active: int, reason: str, expires_at: int):
        async with aiosqlite.connect(self.db_path) as db:
            if active:
                await db.execute('''INSERT INTO lockdown_state (chat_id, active, reason, expires_at) VALUES (?, ?, ?, ?) ON CONFLICT(chat_id) DO UPDATE SET active=1, reason=excluded.reason, expires_at=excluded.expires_at''', (chat_id, active, reason, expires_at))
            else:
                await db.execute("DELETE FROM lockdown_state WHERE chat_id=?", (chat_id,))
            await db.commit()

    async def persist_captcha(self, chat_id: int, user_id: int, message_id: int, expires_at: int, remove: bool = False):
        async with aiosqlite.connect(self.db_path) as db:
            if remove:
                await db.execute("DELETE FROM captcha_registry WHERE chat_id=? AND user_id=?", (chat_id, user_id))
            else:
                await db.execute('''INSERT INTO captcha_registry (chat_id, user_id, message_id, expires_at) VALUES (?, ?, ?, ?) ON CONFLICT(chat_id, user_id) DO UPDATE SET message_id=excluded.message_id, expires_at=excluded.expires_at''', (chat_id, user_id, message_id, expires_at))
            await db.commit()

    async def add_warning_atomic(self, chat_id: int, user_id: int) -> int:
        async with aiosqlite.connect(self.db_path) as db:
            await db.execute('''INSERT INTO warnings (chat_id, user_id, count) VALUES (?, ?, 1) ON CONFLICT(chat_id, user_id) DO UPDATE SET count = count + 1''', (chat_id, user_id))
            await db.commit()
            async with db.execute("SELECT count FROM warnings WHERE chat_id=? AND user_id=?", (chat_id, user_id)) as cursor:
                row = await cursor.fetchone()
                return row[0] if row else 1

    async def reset_warnings_atomic(self, chat_id: int, user_id: int):
        async with aiosqlite.connect(self.db_path) as db:
            await db.execute("DELETE FROM warnings WHERE chat_id=? AND user_id=?", (chat_id, user_id))
            await db.commit()

    async def log_action(self, chat_id: int, user_id: int, admin_id: int, action: str, reason: str, text: str = ""):
        async with aiosqlite.connect(self.db_path) as db:
            await db.execute("INSERT INTO mod_logs (chat_id, user_id, admin_id, action, reason, target_text) VALUES (?, ?, ?, ?, ?, ?)", (chat_id, user_id, admin_id, action, reason, text[:300]))
            await db.commit()

    async def is_whitelisted(self, chat_id: int, user_id: int) -> bool:
        if user_id == OWNER_ID: return True
        async with aiosqlite.connect(self.db_path) as db:
            async with db.execute("SELECT 1 FROM whitelist WHERE chat_id=? AND user_id=?", (chat_id, user_id)) as cursor:
                return (await cursor.fetchone()) is not None

db_layer = DatabaseLayer()

# ------------------------------------------------------------------
# SECURITIES & TEXT REGEX ENGINES
# ------------------------------------------------------------------
def normalize_and_clean_text(text: str) -> str:
    if not text: return ""
    text = re.sub(r'[\u200B-\u200D\uFEFF\x00-\x1F\x7F]', '', text)
    text = unicodedata.normalize('NFKC', text)
    return re.sub(r'[\s\W_]+', '', text).lower()

def scan_obfuscated_links(text: str) -> str:
    if not text: return ""
    pattern = r'\b([a-zA-Z0-9-]+)\s*(\[dot\]|\(dot\)|\.|\s+dot\s+)\s*([a-zA-Z]{2,6})\b'
    matches = re.findall(pattern, text, re.IGNORECASE)
    for p1, _, p2 in matches:
        domain = f"{p1}.{p2}".lower()
        if domain not in TRUSTED_DOMAINS:
            return f"Obfuscated domain: {domain}"
    return ""

def scan_entities_for_links(msg, text: str) -> str:
    entities = msg.entities or msg.caption_entities or []
    mention_count = 0
    for ent in entities:
        if ent.type in [MessageEntity.URL, MessageEntity.TEXT_LINK]:
            url = ent.url or text[ent.offset:ent.offset+ent.length]
            try:
                from urllib.parse import urlparse
                domain = urlparse(url if url.startswith('http') else f'http://{url}').netloc.lower().removeprefix('www.')
                if domain in TRUSTED_DOMAINS: continue
                if re.search(r'(bit\.ly|t\.co|tinyurl|is\.gd|cutt\.ly|linktr\.ee|t\.me/\+)', url, re.IGNORECASE):
                    return "Unauthorized shortlink deployment"
            except Exception:
                return "Malformed link tracking payload"
        if ent.type == MessageEntity.MENTION:
            mention_count += 1
    if mention_count > 4: return "Mass Mention Flood Trigger"
    return ""

# ------------------------------------------------------------------
# TIMEOUTS & STATE RECOVERY REAPERS
# ------------------------------------------------------------------
async def execute_direct_unban_eviction(bot: telegram.Bot, chat_id: int, user_id: int, message_id: int):
    try: 
        await bot.ban_chat_member(chat_id, user_id)
        await bot.unban_chat_member(chat_id, user_id)
    except TelegramError: pass
    try: await bot.delete_message(chat_id, message_id)
    except TelegramError: pass
    await db_layer.persist_captcha(chat_id, user_id, message_id, 0, remove=True)
    captcha_registry[chat_id].pop(user_id, None)

async def verify_timeout_reaper(bot: telegram.Bot, chat_id: int, user_id: int, target_msg_id: int, wait_duration: float):
    await asyncio.sleep(wait_duration)
    async with aiosqlite.connect(db_layer.db_path) as db:
        async with db.execute("SELECT message_id FROM captcha_registry WHERE chat_id=? AND user_id=?", (chat_id, user_id)) as cursor:
            row = await cursor.fetchone()
            if row and row[0] == target_msg_id:
                await execute_direct_unban_eviction(bot, chat_id, user_id, target_msg_id)

async def lift_lockdown_directly(bot: telegram.Bot, chat_id: int):
    lockdown_state[chat_id] = False
    await db_layer.persist_lockdown(chat_id, 0, "", 0)
    try:
        full = ChatPermissions(can_send_messages=True, can_send_audios=True, can_send_documents=True, can_send_photos=True, can_send_videos=True, can_send_other_messages=True, can_add_web_page_previews=True)
        await bot.set_chat_permissions(chat_id, full)
        await bot.send_message(chat_id, "🔓 <b>Lockdown Cleared.</b> Channel pipelines normalized.", parse_mode=ParseMode.HTML)
    except TelegramError: pass

async def lockdown_expiry_timer(bot: telegram.Bot, chat_id: int, wait_duration: float):
    await asyncio.sleep(wait_duration)
    if lockdown_state[chat_id]: await lift_lockdown_directly(bot, chat_id)

async def execute_recovery_synchronization(app: Application):
    now = int(time.time())
    async with aiosqlite.connect(db_layer.db_path) as db:
        async with db.execute("SELECT chat_id, expires_at, reason FROM lockdown_state WHERE active = 1") as cursor:
            lockdowns = await cursor.fetchall()
    for chat_id, expires_at, reason in lockdowns:
        if expires_at <= now: await lift_lockdown_directly(app.bot, chat_id)
        else:
            lockdown_state[chat_id] = True
            asyncio.create_task(lockdown_expiry_timer(app.bot, chat_id, float(expires_at - now)))

    async with aiosqlite.connect(db_layer.db_path) as db:
        async with db.execute("SELECT chat_id, user_id, message_id, expires_at FROM captcha_registry") as cursor:
            captchas = await cursor.fetchall()
    for chat_id, user_id, message_id, expires_at in captchas:
        if expires_at <= now: await execute_direct_unban_eviction(app.bot, chat_id, user_id, message_id)
        else:
            captcha_registry[chat_id][user_id] = message_id
            asyncio.create_task(verify_timeout_reaper(app.bot, chat_id, user_id, message_id, float(expires_at - now)))

async def memory_janitor():
    while True:
        await asyncio.sleep(120)
        now = time.time()
        try:
            for cache in [flood_cache, media_cache]:
                for cid in list(cache.keys()):
                    for uid in list(cache[cid].keys()):
                        cache[cid][uid] = [t for t in cache[cid][uid] if now - t < 30]
                        if not cache[cid][uid]: del cache[cid][uid]
                    if not cache[cid]: del cache[cid]
        except Exception: pass

# ------------------------------------------------------------------
# ENFORCEMENT PUNISHMENT SYSTEMS
# ------------------------------------------------------------------
async def execute_local_punishment(context: ContextTypes.DEFAULT_TYPE, chat_id: int, user_id: int, msg_id: int, reason: str, username: str, immediate_ban: bool = False):
    try: await context.bot.delete_message(chat_id, msg_id)
    except TelegramError: pass

    if immediate_ban:
        try:
            await context.bot.ban_chat_member(chat_id, user_id)
            await db_layer.log_action(chat_id, user_id, 0, "IMMEDIATE_BAN", reason)
            await context.bot.send_message(chat_id, f"🛑 <b>Instant Shield Ban Applied</b>\n<b>User:</b> {username}\n<b>Reason:</b> {reason}", parse_mode=ParseMode.HTML)
        except TelegramError: pass
        return

    warnings = await db_layer.add_warning_atomic(chat_id, user_id)
    if warnings == 1:
        await db_layer.log_action(chat_id, user_id, 0, "WARN", reason)
        await context.bot.send_message(chat_id, f"⚠️ <b>Warning (1/3):</b> {username}\n<b>Reason:</b> {reason}", parse_mode=ParseMode.HTML)
    elif warnings == 2:
        until = int(time.time()) + 3600
        try:
            await context.bot.restrict_chat_member(chat_id, user_id, permissions=ChatPermissions(can_send_messages=False), until_date=until)
            await db_layer.log_action(chat_id, user_id, 0, "TEMPMUTE", reason)
            await context.bot.send_message(chat_id, f"🔇 <b>Muted (1 Hour):</b> {username}\n<b>Reason:</b> {reason}", parse_mode=ParseMode.HTML)
        except TelegramError: pass
    else:
        try:
            await context.bot.ban_chat_member(chat_id, user_id)
            await db_layer.log_action(chat_id, user_id, 0, "BAN", reason)
            await db_layer.reset_warnings_atomic(chat_id, user_id)
            await context.bot.send_message(chat_id, f"🛑 <b>Permanent Ban:</b> {username}\n<b>Reason:</b> {reason} (Warnings Exhausted)", parse_mode=ParseMode.HTML)
        except TelegramError: pass

async def evaluate_via_groq(text: str) -> dict:
    """Uses Groq Cloud API endpoint for extremely fast scanning."""
    if not ai_client: return {"violation": False, "action": "ignore"}
    prompt = (
        "You are an automated chat defense filter. Check this text for advanced stealth scams, "
        "hacking exploits, raid setups, or malicious intent across mixed Hindi/English text. "
        "Respond ONLY with a standard raw JSON structure: "
        '{"violation": true/false, "action": "ban"/"mute"/"ignore", "confidence": 0-100, "reason": "summary"}'
    )
    try:
        res = await ai_client.chat.completions.create(
            model=GROQ_MODEL, 
            response_format={"type": "json_object"}, # Groq supports JSON mode for Llama-3 models
            messages=[{"role": "system", "content": prompt}, {"role": "user", "content": text}],
            max_tokens=120, 
            temperature=0.0
        )
        return json.loads(res.choices[0].message.content)
    except Exception as e: 
        logger.error(f"Groq evaluation error: {e}")
        return {"violation": False, "action": "ignore"}

# ------------------------------------------------------------------
# CORE INGESTION TRIAGE ENGINE
# ------------------------------------------------------------------
async def ingestion_pipeline(update: Update, context: ContextTypes.DEFAULT_TYPE):
    msg = update.effective_message
    chat = update.effective_chat
    user = update.effective_user
    if not msg or not chat or not user or user.is_bot: return
    if msg.sender_chat and msg.sender_chat.id == chat.id: return 

    await db_layer.register_chat(chat.id, chat.title)
    if lockdown_state[chat.id]:
        try: await context.bot.delete_message(chat.id, msg.message_id)
        except TelegramError: pass
        return

    if await is_chat_admin(context.bot, chat.id, user.id) or await db_layer.is_whitelisted(chat.id, user.id): return

    raw_text = msg.text or msg.caption or ""
    normalized_text = normalize_and_clean_text(raw_text)
    username = f"@{user.username}" if user.username else user.first_name
    now = time.time()

    # --- TIER 1: INSTANT LOCAL ENGINE MATCH (Fast Regex & Files) ---
    if PROFANITY_REGEX.search(normalized_text) or PROFANITY_REGEX.search(raw_text):
        return await execute_local_punishment(context, chat.id, user.id, msg.message_id, "Profanity / Abuse Detected", username)
    if SCAM_KEYWORDS.search(normalized_text) or SCAM_KEYWORDS.search(raw_text):
        return await execute_local_punishment(context, chat.id, user.id, msg.message_id, "Scam/Phishing Payload", username, immediate_ban=True)
    if msg.document and os.path.splitext((msg.document.file_name or "").lower())[1] in BANNED_EXTENSIONS:
        return await execute_local_punishment(context, chat.id, user.id, msg.message_id, "Prohibited Executable Payload", username, immediate_ban=True)

    link_violation = scan_entities_for_links(msg, raw_text) or scan_obfuscated_links(raw_text)
    if link_violation: return await execute_local_punishment(context, chat.id, user.id, msg.message_id, link_violation, username)

    flood_cache[chat.id][user.id].append(now)
    if len([t for t in flood_cache[chat.id][user.id] if now - t < 4.0]) >= 5:
        return await execute_local_punishment(context, chat.id, user.id, msg.message_id, "Text Burst Flood", username, immediate_ban=True)

    # --- TIER 2: GOOGLE PERSPECTIVE WEB API ---
    if PERSPECTIVE_API_KEY and len(raw_text.strip()) > 2:
        toxicity_score = await check_perspective_toxicity(raw_text)
        if toxicity_score > 0.82:
            return await execute_local_punishment(context, chat.id, user.id, msg.message_id, f"Multi-lingual Slang API Trigger ({int(toxicity_score*100)}%)", username)

    # --- TIER 3: GROQ AI DEEP CONTEXT EVALUATION ---
    if ai_client and len(raw_text.strip()) > 6:
        ai_res = await evaluate_via_groq(raw_text)
        if ai_res.get("violation") and ai_res.get("confidence", 0) >= 80:
            action = ai_res.get("action", "ban")
            reason = f"Groq AI Flagged: {ai_res.get('reason')}"
            
            try: await context.bot.delete_message(chat.id, msg.message_id)
            except TelegramError: pass
            
            if action == "ban":
                await context.bot.ban_chat_member(chat.id, user_id=user.id)
                await db_layer.log_action(chat_id, user.id, 0, "AI_AUTONOMOUS_BAN", reason)
                await context.bot.send_message(chat_id, f"🛑 <b>Autonomous Groq AI Ban Executed</b>\n<b>User:</b> {username}\n<b>Reason:</b> {reason}", parse_mode=ParseMode.HTML)
            elif action == "mute":
                until = int(time.time()) + 3600
                await context.bot.restrict_chat_member(chat_id, user.id, permissions=ChatPermissions(can_send_messages=False), until_date=until)
                await db_layer.log_action(chat_id, user.id, 0, "AI_AUTONOMOUS_MUTE", reason)
                await context.bot.send_message(chat_id, f"🔇 <b>Autonomous Groq AI Mute Applied (1Hr)</b>\n<b>User:</b> {username}\n<b>Reason:</b> {reason}", parse_mode=ParseMode.HTML)

# ------------------------------------------------------------------
# SYSTEM GATEKEEPERS & RECOVERY INITIALIZERS
# ------------------------------------------------------------------
async def gatekeeper_join_handler(update: Update, context: ContextTypes.DEFAULT_TYPE):
    chat = update.effective_chat
    if not update.message or not update.message.new_chat_members: return
    now = time.time()
    await db_layer.register_chat(chat.id, chat.title)
    new_humans = [m for m in update.message.new_chat_members if not m.is_bot]
    if not new_humans: return

    join_cache[chat.id].extend([now] * len(new_humans))
    if len([t for t in join_cache[chat.id] if now - t < 10.0]) > 6:
        await db_layer.persist_lockdown(chat.id, 1, "Raid Vector Attack", int(time.time())+600)
        for h in new_humans: 
            try: await context.bot.ban_chat_member(chat.id, h.id)
            except TelegramError: pass
        return

    for human in new_humans:
        try:
            await context.bot.restrict_chat_member(chat.id, human.id, permissions=ChatPermissions(can_send_messages=False))
            kb = [[InlineKeyboardButton("🔒 Pass Gate", callback_data=f"gate_{human.id}")]]
            out = await context.bot.send_message(chat.id, f"🛡️ Welcome. Verify identity within 60 seconds.", reply_markup=InlineKeyboardMarkup(kb))
            await db_layer.persist_captcha(chat.id, human.id, out.message_id, int(time.time()) + 60)
            captcha_registry[chat.id][human.id] = out.message_id
            asyncio.create_task(verify_timeout_reaper(context.bot, chat.id, human.id, out.message_id, 60.0))
        except TelegramError: pass

async def process_gate_callback(update: Update, context: ContextTypes.DEFAULT_TYPE):
    query = update.callback_query
    user_id = query.from_user.id
    chat_id = query.message.chat_id
    try: target_id = int(query.data.split("_")[1])
    except Exception: return

    if user_id != target_id: return await query.answer("❌ Challenge access denied.", show_alert=True)
    if chat_id in captcha_registry and user_id in captcha_registry[chat_id]:
        try:
            full = ChatPermissions(can_send_messages=True, can_send_audios=True, can_send_documents=True, can_send_photos=True, can_send_videos=True, can_send_other_messages=True, can_add_web_page_previews=True)
            await context.bot.restrict_chat_member(chat_id, user_id, permissions=full)
            await context.bot.delete_message(chat_id, query.message.message_id)
            await query.answer("Matrix Access Granted.", show_alert=True)
        except TelegramError: pass
        finally:
            await db_layer.persist_captcha(chat_id, user_id, query.message.message_id, 0, remove=True)
            captcha_registry[chat_id].pop(user_id, None)

async def is_chat_admin(bot, chat_id: int, user_id: int) -> bool:
    if user_id == OWNER_ID: return True
    if chat_id in admin_cache and (time.time() - admin_cache[chat_id]['time']) < 1800: return user_id in admin_cache[chat_id]['list']
    try:
        admins = await bot.get_chat_administrators(chat_id)
        alist = [a.user.id for a in admins]
        admin_cache[chat_id] = {'list': alist, 'time': time.time()}
        return user_id in alist
    except TelegramError: return False

async def post_startup_validation(app: Application):
    await db_layer.init_db()
    asyncio.create_task(memory_janitor())
    await execute_recovery_synchronization(app)
    logger.info("🛡️ Multi-Tier Hybrid Production Core Firewall Activated.")

def main():
    if not TELEGRAM_BOT_TOKEN: 
        logger.error("Bhai, TELEGRAM_BOT_TOKEN missing hai!")
        return
        
    app = Application.builder().token(TELEGRAM_BOT_TOKEN).post_init(post_startup_validation).build()
    
    # Handlers Setup
    app.add_handler(CallbackQueryHandler(process_gate_callback, pattern=r"^gate_"))
    app.add_handler(MessageHandler(filters.StatusUpdate.NEW_CHAT_MEMBERS, gatekeeper_join_handler))
    app.add_handler(MessageHandler(filters.TEXT | filters.COMMAND, ingestion_pipeline))
    
    # WEBHOOK OR POLLING DEPLOYMENT LOGIC (RENDER SAFE)
    if WEBHOOK_URL:
        logger.info(f"🛡️ Starting bot with WEBHOOK on port {PORT}...")
        app.run_webhook(
            listen="0.0.0.0",
            port=PORT,
            url_path=TELEGRAM_BOT_TOKEN,
            webhook_url=f"{WEBHOOK_URL}/{TELEGRAM_BOT_TOKEN}"
        )
    else:
        logger.info("🛡️ Starting bot with POLLING (Local Environment)...")
        app.run_polling(allowed_updates=Update.ALL_TYPES)

if __name__ == "__main__":
    main()
