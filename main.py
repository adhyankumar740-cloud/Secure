import os
import re
import time
import json
import math
import asyncio
import logging
import unicodedata
import aiosqlite
import telegram
import httpx
from collections import defaultdict
from urllib.parse import urlparse
from dotenv import load_dotenv

# MongoDB Async Driver for Permanent Storage
from motor.motor_asyncio import AsyncIOMotorClient

from telegram import (
    Update, 
    ChatPermissions, 
    InlineKeyboardButton, 
    InlineKeyboardMarkup,
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
from openai import AsyncOpenAI

try:
    from rapidfuzz import fuzz
    RAPIDFUZZ_AVAILABLE = True
except ImportError:
    RAPIDFUZZ_AVAILABLE = False

# ------------------------------------------------------------------
# CONFIGURATION & ENVIRONMENT SETUP
# ------------------------------------------------------------------
logging.basicConfig(
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    level=logging.INFO
)
logger = logging.getLogger("MaximumSecurityMod")
logging.getLogger("httpx").setLevel(logging.WARNING)

try:
    import edge_tts
    EDGE_TTS_AVAILABLE = True
except ImportError:
    EDGE_TTS_AVAILABLE = False
    logger.warning("edge_tts not installed — voice warnings disabled")

if not RAPIDFUZZ_AVAILABLE:
    logger.warning("rapidfuzz not installed — fuzzy profanity matching disabled (pip install rapidfuzz)")

load_dotenv()
TELEGRAM_BOT_TOKEN = os.getenv("TELEGRAM_BOT_TOKEN")
OWNER_ID = int(os.getenv("OWNER_ID", "0"))
MONGO_URI = os.getenv("MONGO_URI")

GROQ_API_KEY = os.getenv("GROQ_API_KEY") # Main Task Moderation Key
GROQ_API_KEY_2 = os.getenv("GROQ_API_KEY_2")  # Dedicated Key for Voice Transcriptions & Daily "Trailer" Engagement
GROQ_MODEL = os.getenv("GROQ_MODEL", "llama-3.1-8b-instant") 
HF_API_KEY = os.getenv("HF_API_KEY")

WEBHOOK_URL = os.getenv("WEBHOOK_URL")
PORT = int(os.getenv("PORT", "8000"))

# ------------------------------------------------------------------
# UPGRADED PROFANITY DETECTION ENGINE
# ------------------------------------------------------------------
# Layer A: existing compiled regex (kept from before — fast first pass)
PROFANITY_REGEX = re.compile(
    r'(bh[e3]nchod|madar[c]hod|ch[u0]t[i1]ya|\bg[a@]nd\b|l[u0]nd|b[e3]h[e3]nchod|'
    r'r[a@]ndi|\bs[a@]l[a@]\b|k[a@]m[i1]n[a@]|f+u+c+k+|sh[i1]t+|b[i1]tch|'
    r'[a@]ssh[o0]l[e3]|b[e3]wk[o0]of|h[a@]r[a@]mi|g[a@]ndu|\bch[u0]t\b|'
    r'lodu|chodu|bsdk|\bmc\b|\bbc\b|\bmf\b)',
    re.IGNORECASE
)

# Layer B: root-word skeleton list — catches spaced-out / broken-up variants
# ("m c", "m.c", "m a d a r c h o d") that the regex above can miss because
# it expects the letters to be contiguous.
ABUSE_ROOTS = [
    "mc", "mdrchd", "bc", "bhnchd", "chutiya", "chtiya", "randi",
    "harami", "haraami", "kutta", "kutti", "saala", "saali",
    "gaand", "gand", "lund", "lauda", "loda", "chinaal", "raand",
    "bhosdi", "bhosda", "bsdk", "gandu", "chodu", "chod", "mf",
    "fuck", "bitch", "asshole", "bewkoof",
]
FUZZY_THRESHOLD = 82  # 0-100, higher = stricter

_LEET_MAP = str.maketrans({
    "0": "o", "1": "i", "3": "e", "4": "a", "5": "s",
    "7": "t", "8": "b", "@": "a", "$": "s",
})

SCAM_KEYWORDS = re.compile(r'(crypto_help|support_desk|air_drop|binance_support|trust_wallet|free_tokens|claim_airdrop|invest_money|double_funds)', re.IGNORECASE)
BANNED_EXTENSIONS = {'.exe', '.apk', '.bat', '.scr', '.vbs', '.iso', '.dmg', '.msi', '.sh', '.cmd', '.pif'}
TRUSTED_DOMAINS = {'youtube.com', 'youtu.be', 'wikipedia.org', 'github.com', 'google.com', 't.me'}

def normalize_for_profanity(text: str) -> str:
    """
    Upgraded normalizer. Removes spaces/symbols between letters, converts
    leetspeak, and collapses repeated letters, so bypass tricks like
    "m . c", "m@d@rch0d", "gaaaali" all reduce to a clean matchable form.
    """
    text = text.lower()
    text = text.translate(_LEET_MAP)
    text = re.sub(r'[._\-*~`^]', '', text)
    text = re.sub(r'(.)\1{2,}', r'\1', text)                  # collapse repeated letters
    text = re.sub(r'\b(\w)\s+(?=\w\b)', r'\1', text)          # join single-letter-spaced words
    text = re.sub(r'\s+', ' ', text).strip()
    return text


def _strip_vowels(word: str) -> str:
    return re.sub(r'[aeiou]', '', word)


def rule_based_profanity_check(raw_text: str) -> bool:
    """
    Combines: (1) the original compiled regex, (2) root-skeleton matching,
    (3) fuzzy matching, and (4) the large word/phrase database loaded from
    disk (see load_bad_words_database below) — so contiguous slurs, spaced-out
    variants, typos, AND thousands of known bad words/phrases all get caught
    in one pass, without hand-maintaining a giant exact-spelling list.
    """
    if not raw_text:
        return False

    normalized = normalize_for_profanity(raw_text)

    # (1) Original regex, run against raw + normalized text
    if PROFANITY_REGEX.search(raw_text) or PROFANITY_REGEX.search(normalized):
        return True

    # (2) & (3) Root-skeleton + fuzzy matching
    words = normalized.split()
    candidates = words + [normalized]
    for candidate in candidates:
        skeleton = _strip_vowels(candidate)
        for root in ABUSE_ROOTS:
            root_skeleton = _strip_vowels(root)
            if root in candidate or (root_skeleton and root_skeleton in skeleton):
                return True
            if RAPIDFUZZ_AVAILABLE and len(candidate) >= 3:
                if fuzz.ratio(candidate, root) >= FUZZY_THRESHOLD:
                    return True

    # (4) Large bad-words/phrases database (word-boundary safe matching)
    if _SINGLE_WORD_DB_REGEX and _SINGLE_WORD_DB_REGEX.search(normalized):
        return True
    if _PHRASE_DB_REGEX and _PHRASE_DB_REGEX.search(normalized):
        return True

    return False


# ------------------------------------------------------------------
# LARGE BAD-WORDS/PHRASES DATABASE (loaded from JSON on disk)
# ------------------------------------------------------------------
# Set BAD_WORDS_DB_PATH env var to switch between:
#   data/bad_words_curated.json  (default, safer — generic/ambiguous English
#                                  words like "sick", "toilet", "virgin",
#                                  "welfare", "damn", "hell" etc. removed to
#                                  avoid false-positives in normal chat)
#   data/bad_words_full.json     (raw extracted list, maximum strictness,
#                                  but WILL false-positive on common words)
def load_bad_words_database(path: str):
    """
    Loads a JSON array of words/phrases, normalizes each entry the same way
    incoming messages are normalized, and splits them into:
      - single-word entries -> combined into one word-boundary regex
      - multi-word phrases  -> combined into one boundary-safe regex
    Word-boundary matching means "ass" won't match inside "class", etc.
    """
    with open(path, "r", encoding="utf-8") as f:
        raw_entries = json.load(f)

    single_words, phrases = set(), set()
    for entry in raw_entries:
        norm = normalize_for_profanity(entry)
        if not norm:
            continue
        if " " in norm:
            phrases.add(norm)
        else:
            single_words.add(norm)

    single_regex = None
    if single_words:
        escaped = sorted((re.escape(w) for w in single_words), key=len, reverse=True)
        single_regex = re.compile(r'\b(?:' + '|'.join(escaped) + r')\b', re.IGNORECASE)

    phrase_regex = None
    if phrases:
        escaped = sorted((re.escape(p) for p in phrases), key=len, reverse=True)
        phrase_regex = re.compile(r'\b(?:' + '|'.join(escaped) + r')\b', re.IGNORECASE)

    return single_regex, phrase_regex, len(single_words), len(phrases)


_DATA_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "data")
BAD_WORDS_DB_PATH = os.getenv("BAD_WORDS_DB_PATH", os.path.join(_DATA_DIR, "bad_words_curated.json"))

_SINGLE_WORD_DB_REGEX = None
_PHRASE_DB_REGEX = None
try:
    _SINGLE_WORD_DB_REGEX, _PHRASE_DB_REGEX, _n_single, _n_phrase = load_bad_words_database(BAD_WORDS_DB_PATH)
    logger.info(f"Loaded bad-words database from {BAD_WORDS_DB_PATH}: {_n_single} words, {_n_phrase} phrases.")
except Exception as e:
    logger.warning(f"Could not load bad-words database ({BAD_WORDS_DB_PATH}): {e} — continuing without it.")


# --- ADVANCED GLOBAL ENGINE STATE & CACHES ---
admin_cache = {}
flood_cache = defaultdict(lambda: defaultdict(list))
mass_report_cache = defaultdict(lambda: defaultdict(list))
media_fingerprint_cache = defaultdict(lambda: defaultdict(dict)) 
behavioral_velocity_cache = defaultdict(lambda: defaultdict(list))
lockdown_state = defaultdict(bool)
captcha_registry = defaultdict(dict)
global_chat_velocity = defaultdict(list)
join_cache = defaultdict(list)

# AI Client Declarations (Separated Matrix)
groq_client = AsyncOpenAI(api_key=GROQ_API_KEY, base_url="https://api.groq.com/openai/v1") if GROQ_API_KEY else None
groq_2 = AsyncOpenAI(api_key=GROQ_API_KEY_2, base_url="https://api.groq.com/openai/v1") if GROQ_API_KEY_2 else None

HOMOGLYPH_MAP = {
    'а': 'a', 'в': 'b', 'е': 'e', 'к': 'k', 'м': 'm', 'н': 'n', 'о': 'o', 'р': 'p',
    'с': 's', 'т': 'm', 'х': 'x', 'у': 'y', 'ѕ': 's', 'і': 'i', 'ј': 'j', '👁️': 'i',
    '𝔲': 'u', '𝔠': 'c', '𝔨': 'k', '𝔣': 'f', '𝔲': 'u', '𝔠': 'c', '𝔥': 'h', '泡沫': 'scam'
}

# ------------------------------------------------------------------
# HYBRID DATABASE LAYER: SQLite (RAM Speed) + MongoDB (Permanent)
# ------------------------------------------------------------------
class HybridDatabaseLayer:
    def __init__(self, db_path="max_security_mod.db"):
        self.db_path = db_path
        self.mongo_client = None
        self.mongo_db = None

    async def init_db(self):
        # Local RAM / High-Speed SQLite Cache
        async with aiosqlite.connect(self.db_path) as db:
            await db.execute("PRAGMA journal_mode=WAL;")
            await db.execute("PRAGMA synchronous=NORMAL;")
            await db.execute('''CREATE TABLE IF NOT EXISTS warnings (chat_id INTEGER, user_id INTEGER, count INTEGER, PRIMARY KEY(chat_id, user_id))''')
            await db.execute('''CREATE TABLE IF NOT EXISTS mod_logs (id INTEGER PRIMARY KEY AUTOINCREMENT, chat_id INTEGER, user_id INTEGER, admin_id INTEGER, action TEXT, reason TEXT, target_text TEXT, timestamp DATETIME DEFAULT CURRENT_TIMESTAMP)''')
            await db.execute('''CREATE TABLE IF NOT EXISTS whitelist (chat_id INTEGER, user_id INTEGER, PRIMARY KEY(chat_id, user_id))''')
            await db.execute('''CREATE TABLE IF NOT EXISTS lockdown_state (chat_id INTEGER PRIMARY KEY, active INTEGER, reason TEXT, expires_at INTEGER)''')
            await db.execute('''CREATE TABLE IF NOT EXISTS captcha_registry (chat_id INTEGER, user_id INTEGER, message_id INTEGER, expires_at INTEGER, PRIMARY KEY(chat_id, user_id))''')
            await db.execute('''CREATE TABLE IF NOT EXISTS managed_chats (chat_id INTEGER PRIMARY KEY, title TEXT, added_at DATETIME DEFAULT CURRENT_TIMESTAMP)''')
            await db.execute('''CREATE TABLE IF NOT EXISTS user_reputation (chat_id INTEGER, user_id INTEGER, reputation_score REAL DEFAULT 100.0, total_messages INTEGER DEFAULT 0, risk_factor TEXT DEFAULT 'LOW', last_seen INTEGER, PRIMARY KEY(chat_id, user_id))''')
            await db.execute('''CREATE TABLE IF NOT EXISTS invite_chains (chat_id INTEGER, user_id INTEGER, inviter_id INTEGER, invite_link_used TEXT, join_timestamp INTEGER, PRIMARY KEY(chat_id, user_id))''')
            await db.execute('''CREATE TABLE IF NOT EXISTS persistent_media_hashes (chat_id INTEGER, file_hash TEXT, incident_count INTEGER DEFAULT 1, payload_type TEXT, last_seen INTEGER, PRIMARY KEY(chat_id, file_hash))''')
            await db.commit()
            
        logger.info("⚡ SQLite Front-line RAM caching engine synchronized.")

        # MongoDB Cloud Connection Matrix
        if MONGO_URI:
            try:
                self.mongo_client = AsyncIOMotorClient(MONGO_URI)
                self.mongo_db = self.mongo_client["phantom_security_vault"]
                await self.mongo_db["user_reputation"].create_index([("chat_id", 1), ("user_id", 1)], unique=True)
                await self.mongo_db["whitelist"].create_index([("chat_id", 1), ("user_id", 1)], unique=True)
                await self.mongo_db["managed_chats"].create_index([("chat_id", 1)], unique=True)
                logger.info("🛸 Distributed MongoDB Long-Term Cloud Storage connected successfully.")
            except Exception as e:
                logger.error(f"❌ Critical failure initializing MongoDB Cloud: {e}")
        else:
            logger.warning("⚠️ MONGO_URI missing. Falling back to local SQLite only.")

    async def register_chat(self, chat_id: int, title: str):
        async with aiosqlite.connect(self.db_path) as db:
            await db.execute('''INSERT INTO managed_chats (chat_id, title) VALUES (?, ?) ON CONFLICT(chat_id) DO UPDATE SET title = excluded.title''', (chat_id, title or "Unknown Chat Group"))
            await db.commit()
            
        if self.mongo_db is not None:
            try:
                await self.mongo_db["managed_chats"].update_one(
                    {"chat_id": chat_id},
                    {"$set": {"title": title or "Unknown Chat Group", "updated_at": int(time.time())}},
                    upsert=True
                )
            except Exception: pass

    async def get_all_managed_chats(self) -> list:
        if self.mongo_db is not None:
            try:
                cursor = self.mongo_db["managed_chats"].find({})
                chats = await cursor.to_list(length=1000)
                return [c["chat_id"] for c in chats]
            except Exception: pass
            
        async with aiosqlite.connect(self.db_path) as db:
            async with db.execute("SELECT chat_id FROM managed_chats") as cursor:
                rows = await cursor.fetchall()
                return [r[0] for r in rows]

    async def update_user_reputation(self, chat_id: int, user_id: int, delta: float) -> tuple:
        now = int(time.time())
        async with aiosqlite.connect(self.db_path) as db:
            await db.execute('''INSERT INTO user_reputation (chat_id, user_id, reputation_score, total_messages, last_seen) 
                                VALUES (?, ?, 100.0 + ?, 1, ?) 
                                ON CONFLICT(chat_id, user_id) 
                                DO UPDATE SET reputation_score = MAX(0.0, MIN(100.0, reputation_score + ?)), total_messages = total_messages + 1, last_seen = ?''', 
                             (chat_id, user_id, delta, now, delta, now))
            await db.commit()
            async with db.execute("SELECT reputation_score, total_messages FROM user_reputation WHERE chat_id=? AND user_id=?", (chat_id, user_id)) as cursor:
                row = await cursor.fetchone()
                score, total_msg = row if row else (100.0, 1)

        if self.mongo_db is not None:
            try:
                await self.mongo_db["user_reputation"].update_one(
                    {"chat_id": chat_id, "user_id": user_id},
                    {
                        "$setOnInsert": {"initial_joined": now},
                        "$set": {"reputation_score": score, "total_messages": total_msg, "last_seen": now}
                    },
                    upsert=True
                )
            except Exception: pass
            
        return score, total_msg

    async def check_duplicate_media_hash(self, chat_id: int, file_hash: str, payload_type: str) -> int:
        async with aiosqlite.connect(self.db_path) as db:
            now = int(time.time())
            async with db.execute("SELECT incident_count FROM persistent_media_hashes WHERE chat_id=? AND file_hash=?", (chat_id, file_hash)) as cursor:
                row = await cursor.fetchone()
                if row:
                    await db.execute("UPDATE persistent_media_hashes SET incident_count = incident_count + 1, last_seen = ? WHERE chat_id=? AND file_hash=?", (now, chat_id, file_hash))
                    await db.commit()
                    return row[0] + 1
                else:
                    await db.execute("INSERT INTO persistent_media_hashes (chat_id, file_hash, incident_count, payload_type, last_seen) VALUES (?, ?, 1, ?, ?)", (chat_id, file_hash, payload_type, now))
                    await db.commit()
                    return 1

    async def get_chat_analytics_summary(self, chat_id: int) -> dict:
        stats = {'total_incidents': 0, 'bans': 0, 'suspicious_users': 0}
        if self.mongo_db is not None:
            try:
                stats['total_incidents'] = await self.mongo_db["mod_logs"].count_documents({"chat_id": chat_id})
                stats['bans'] = await self.mongo_db["mod_logs"].count_documents({"chat_id": chat_id, "action": {"$in": ["BAN", "AI_AUTONOMOUS_BAN", "IMMEDIATE_BAN"]}})
                stats['suspicious_users'] = await self.mongo_db["user_reputation"].count_documents({"chat_id": chat_id, "reputation_score": {"$lt": 50.0}})
                return stats
            except Exception: pass
            
        async with aiosqlite.connect(self.db_path) as db:
            async with db.execute("SELECT COUNT(*) FROM mod_logs WHERE chat_id=?", (chat_id,)) as c: stats['total_incidents'] = (await c.fetchone())[0]
            async with db.execute("SELECT COUNT(*) FROM mod_logs WHERE chat_id=? AND action='BAN'", (chat_id,)) as c: stats['bans'] = (await c.fetchone())[0]
            async with db.execute("SELECT COUNT(*) FROM user_reputation WHERE chat_id=? AND reputation_score < 50.0", (chat_id,)) as c: stats['suspicious_users'] = (await c.fetchone())[0]
            return stats

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
        now_ts = int(time.time())
        async with aiosqlite.connect(self.db_path) as db:
            await db.execute("INSERT INTO mod_logs (chat_id, user_id, admin_id, action, reason, target_text, timestamp) VALUES (?, ?, ?, ?, ?, ?, ?)", (chat_id, user_id, admin_id, action, reason, text[:300], now_ts))
            await db.commit()
        if self.mongo_db is not None:
            try:
                await self.mongo_db["mod_logs"].insert_one({
                    "chat_id": chat_id, "user_id": user_id, "admin_id": admin_id, "action": action, "reason": reason, "target_text": text[:300], "timestamp": now_ts
                })
            except Exception: pass

    async def is_whitelisted(self, chat_id: int, user_id: int) -> bool:
        if user_id == OWNER_ID: return True
        async with aiosqlite.connect(self.db_path) as db:
            async with db.execute("SELECT 1 FROM whitelist WHERE chat_id=? AND user_id=?", (chat_id, user_id)) as cursor:
                return (await cursor.fetchone()) is not None

    async def add_to_whitelist(self, chat_id: int, user_id: int):
        async with aiosqlite.connect(self.db_path) as db:
            await db.execute('''INSERT OR IGNORE INTO whitelist (chat_id, user_id) VALUES (?, ?)''', (chat_id, user_id))
            await db.commit()
        if self.mongo_db is not None:
            try:
                await self.mongo_db["whitelist"].update_one({"chat_id": chat_id, "user_id": user_id}, {"$set": {"added_at": int(time.time())}}, upsert=True)
            except Exception: pass

    async def remove_from_whitelist(self, chat_id: int, user_id: int):
        async with aiosqlite.connect(self.db_path) as db:
            await db.execute("DELETE FROM whitelist WHERE chat_id=? AND user_id=?", (chat_id, user_id))
            await db.commit()
        if self.mongo_db is not None:
            try:
                await self.mongo_db["whitelist"].delete_one({"chat_id": chat_id, "user_id": user_id})
            except Exception: pass

    async def get_whitelist(self, chat_id: int) -> list:
        async with aiosqlite.connect(self.db_path) as db:
            async with db.execute("SELECT user_id FROM whitelist WHERE chat_id=?", (chat_id,)) as cursor:
                rows = await cursor.fetchall()
                return [r[0] for r in rows]

db_layer = HybridDatabaseLayer()

# ------------------------------------------------------------------
# LAYER 1: UNICODE PARSING & ADVANCED DE-OBFUSCATION ENGINE
# ------------------------------------------------------------------
class UnicodeObfuscationEngine:
    @staticmethod
    def deep_clean_and_normalize(text: str) -> tuple:
        if not text: return "", 0.0, 0
        text = re.sub(r'[\u200B-\u200D\uFEFF\x00-\x1F\x7F\u202E]', '', text)
        normalized = unicodedata.normalize('NFKC', text)
        builder = []
        detected_scripts = set() 
        for char in normalized:
            low_char = char.lower()
            resolved_char = HOMOGLYPH_MAP.get(low_char, low_char)
            builder.append(resolved_char)
            try:
                script_name = unicodedata.name(char).split()[0]
                if script_name in ['CYRILLIC', 'GREEK', 'LATIN']: detected_scripts.add(script_name)
            except ValueError: pass

        cleaned_text = "".join(builder)
        structural_text = re.sub(r'[\s\W_]+', '', cleaned_text)
        mixed_scripts_detected = len(detected_scripts) if len(detected_scripts) > 1 else 0
        
        entropy = 0.0
        if structural_text:
            distribution = defaultdict(int)
            for c in structural_text: distribution[c] += 1
            entropy = -sum((count / len(structural_text)) * math.log2(count / len(structural_text)) for count in distribution.values())

        return cleaned_text, entropy, mixed_scripts_detected

# ------------------------------------------------------------------
# LAYER 2: BEHAVIORAL PROFILING & RISK SYSTEMS
# ------------------------------------------------------------------
class BehavioralProfiler:
    @staticmethod
    def calculate_account_trust_score(user_id: int, total_messages: int, reputation: float) -> tuple:
        age_risk = "LOW"
        if user_id > 6500000000: age_risk = "CRITICAL_NEW"
        elif user_id > 5000000000: age_risk = "HIGH_NEW"

        trust_score = 100.0
        if age_risk == "CRITICAL_NEW": trust_score -= 35.0
        if age_risk == "HIGH_NEW": trust_score -= 15.0
        reputation_penalty = (100.0 - reputation) * 1.2
        trust_score -= reputation_penalty
        
        if total_messages > 150: trust_score += 15.0
        final_trust = max(1.0, min(100.0, trust_score))
        return final_trust, age_risk

    @staticmethod
    def analyze_structural_velocity(chat_id: int, user_id: int, current_text: str) -> bool:
        now = time.time()
        user_history = behavioral_velocity_cache[chat_id][user_id]
        user_history.append((now, len(current_text)))
        user_history = [(t, l) for t, l in user_history if now - t < 30.0]
        behavioral_velocity_cache[chat_id][user_id] = user_history
        
        if len(user_history) >= 4:
            lengths = [item[1] for item in user_history]
            variance = sum((x - sum(lengths)/len(lengths)) ** 2 for x in lengths) / len(lengths)
            if variance < 1.5 and len(current_text) > 40: return True 
        return False

def detect_coordinated_spam(chat_id: int, user_id: int) -> bool:
    now = time.time()
    active_users = set()
    for uid, timestamps in flood_cache[chat_id].items():
        recent = [t for t in timestamps if now - t < 5.0]
        if len(recent) >= 2: active_users.add(uid)
    return len(active_users) >= 5

# ------------------------------------------------------------------
# LAYER 3: ADVANCED URL & ARCHIVE PARSERS
# ------------------------------------------------------------------
class InfrastructureInspector:
    @staticmethod
    async def resolve_and_profile_url(text: str) -> tuple:
        urls = re.findall(r'(https?://\S+)', text)
        if not urls: return "", False
        target_url = urls[0]
        try:
            parsed = urlparse(target_url)
            domain = parsed.netloc.lower().removeprefix('www.')
            if domain.count('.') >= 3 and not any(d in domain for d in TRUSTED_DOMAINS):
                return f"Suspicious sub-domain chaining: {domain}", True
            if any(s in domain for s in ['bit.ly', 't.co', 'tinyurl', 'cutt.ly', 'linktr.ee']):
                async with httpx.AsyncClient() as client:
                    res = await client.head(target_url, timeout=2.5, follow_redirects=True)
                    expanded_domain = urlparse(str(res.url)).netloc.lower().removeprefix('www.')
                    if expanded_domain not in TRUSTED_DOMAINS:
                        return f"Deceptive shortlink redirects to unverified domain: {expanded_domain}", True
        except Exception: pass
        return "", False

    @staticmethod
    def inspect_file_structure(filename: str) -> tuple:
        if not filename: return "", False
        filename_lower = filename.lower()
        if len(re.findall(r'\.[a-z0-9]{2,4}', filename_lower)) > 1:
            for ext in BANNED_EXTENSIONS:
                if ext in filename_lower: return f"Malicious multi-extension payload intercepted: {ext}", True
        ext = os.path.splitext(filename_lower)[1]
        if ext in BANNED_EXTENSIONS: return f"Banned executable structure: {ext}", True
        return "", False

def calculate_adaptive_threat_factor(chat_id: int) -> float:
    now = time.time()
    timestamps = global_chat_velocity[chat_id]
    timestamps.append(now)
    timestamps = [t for t in timestamps if now - t < 10.0]
    global_chat_velocity[chat_id] = timestamps
    if len(timestamps) > 25: return 2.5
    if len(timestamps) > 12: return 1.6
    return 1.0

# ------------------------------------------------------------------
# CLOUD BACKENDS (HF TOXIC-BERT + MULTILINGUAL + HINDI HATE-SPEECH)
# ------------------------------------------------------------------
async def check_tier2_2_hf_toxic_bert(text: str) -> bool:
    if not HF_API_KEY or not text.strip(): return False
    url = "https://api-inference.huggingface.co/models/unitary/toxic-bert"
    headers = {"Authorization": f"Bearer {HF_API_KEY}"}
    async with httpx.AsyncClient() as client:
        try:
            response = await client.post(url, json={"inputs": text}, headers=headers, timeout=4.0)
            if response.status_code == 503:
                await asyncio.sleep(2)
                response = await client.post(url, json={"inputs": text}, headers=headers, timeout=4.0)
            if response.status_code == 200:
                data = response.json()
                inner = data[0] if isinstance(data[0], list) else data
                TOXIC_LABELS = {'toxic', 'severe_toxic', 'obscene', 'threat', 'insult', 'identity_hate'}
                for pred in inner:
                    if pred.get('label', '').lower() in TOXIC_LABELS and pred.get('score', 0) > 0.68: return True
        except Exception: pass
    return False

async def check_hf_multilingual(text: str) -> bool:
    if not HF_API_KEY or not text.strip(): return False
    url = "https://api-inference.huggingface.co/models/facebook/roberta-hate-speech-dynabench-r4-target"
    headers = {"Authorization": f"Bearer {HF_API_KEY}"}
    async with httpx.AsyncClient() as client:
        try:
            response = await client.post(url, json={"inputs": text}, headers=headers, timeout=4.0)
            if response.status_code == 503:
                await asyncio.sleep(2)
                response = await client.post(url, json={"inputs": text}, headers=headers, timeout=4.0)
            if response.status_code == 200:
                results = response.json()
                inner = results[0] if isinstance(results[0], list) else results
                for r in inner:
                    if r.get('label', '').lower() == 'hate' and r.get('score', 0) > 0.72: return True
        except Exception: pass
    return False

async def check_hf_hindi_hate_speech(text: str) -> bool:
    """New: dedicated Hindi/Hinglish hate-speech model — extra layer specifically
    for desi profanity/abuse that the general-purpose models above may miss."""
    if not HF_API_KEY or not text.strip(): return False
    url = "https://api-inference.huggingface.co/models/Hate-speech-CNERG/dehatebert-mono-hindi"
    headers = {"Authorization": f"Bearer {HF_API_KEY}"}
    async with httpx.AsyncClient() as client:
        try:
            response = await client.post(url, json={"inputs": text[:512]}, headers=headers, timeout=4.0)
            if response.status_code == 503:
                await asyncio.sleep(2)
                response = await client.post(url, json={"inputs": text[:512]}, headers=headers, timeout=4.0)
            if response.status_code == 200:
                data = response.json()
                inner = data[0] if isinstance(data[0], list) else data
                for pred in inner:
                    label = str(pred.get('label', '')).upper()
                    if label in ('HATE', 'OFFENSIVE', 'LABEL_1', '1') and pred.get('score', 0) > 0.72:
                        return True
        except Exception: pass
    return False

def can_delete_messages(member) -> bool:
    if isinstance(member, ChatMemberOwner): return True
    return bool(getattr(member, 'can_delete_messages', False))

# ------------------------------------------------------------------
# SYSTEM ADMINISTRATION COMMANDS
# ------------------------------------------------------------------
async def start_command_handler(update: Update, context: ContextTypes.DEFAULT_TYPE):
    start_text = (
        "👁️ <b>Maximum Security Matrix Active</b>\n\n"
        "I am a hardened firewall defense engine built to safeguard chats using deep unicode inspection, "
        "adaptive rate throttling, upgraded Hindi/Hinglish profanity detection, and autonomous cloud AI modeling.\n\n"
        "🔧 <b>Available Administrative Directives:</b>\n"
        "• /analytics - Review active threat parameters\n"
        "• /add_white &lt;user_id&gt; - Exception allocation for bots/users\n"
        "• /remove_white &lt;user_id&gt; - Remove automated user exception\n"
        "• /whitelist - Review all whitelisted profiles"
    )
    await update.message.reply_text(start_text, parse_mode=ParseMode.HTML)

async def add_white_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    chat, user = update.effective_chat, update.effective_user
    if not chat or not user or not await is_chat_admin(context.bot, chat.id, user.id):
        return await update.message.reply_text("❌ Administrative authorization required.")
    if not context.args: return await update.message.reply_text("💡 Usage: <code>/add_white <user_id></code>", parse_mode=ParseMode.HTML)
    try:
        target_id = int(context.args[0])
        await db_layer.add_to_whitelist(chat.id, target_id)
        await update.message.reply_text(f"✅ User/Bot ID <code>{target_id}</code> appended to firewall verification exceptions.", parse_mode=ParseMode.HTML)
    except ValueError:
        await update.message.reply_text("❌ Numerical parsing fault. Provide a valid User ID.")

async def remove_white_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    chat, user = update.effective_chat, update.effective_user
    if not chat or not user or not await is_chat_admin(context.bot, chat.id, user.id):
        return await update.message.reply_text("❌ Administrative authorization required.")
    if not context.args: return await update.message.reply_text("💡 Usage: <code>/remove_white <user_id></code>", parse_mode=ParseMode.HTML)
    try:
        target_id = int(context.args[0])
        await db_layer.remove_from_whitelist(chat.id, target_id)
        await update.message.reply_text(f"✅ User/Bot ID <code>{target_id}</code> removed from firewall exceptions.", parse_mode=ParseMode.HTML)
    except ValueError:
        await update.message.reply_text("❌ Numerical parsing fault. Provide a valid User ID.")

async def whitelist_command_handler(update: Update, context: ContextTypes.DEFAULT_TYPE):
    chat, user = update.effective_chat, update.effective_user
    if not chat or not user or not await is_chat_admin(context.bot, chat.id, user.id):
        return await update.message.reply_text("❌ Administrative authorization required.")
    users = await db_layer.get_whitelist(chat.id)
    if not users: return await update.message.reply_text("📋 Whitelist matrix is currently empty.")
    list_str = "📋 <b>Active Firewall Exceptions:</b>\n" + "\n".join([f"• <code>{uid}</code>" for uid in users])
    await update.message.reply_text(list_str, parse_mode=ParseMode.HTML)

# ------------------------------------------------------------------
# CORE INGESTION INTERCEPTOR PIPELINE (TRIAGE ENGINE)
# ------------------------------------------------------------------
async def ingestion_pipeline(update: Update, context: ContextTypes.DEFAULT_TYPE):
    msg, chat, user = update.effective_message, update.effective_chat, update.effective_user
    if not msg or not chat or not user or user.is_bot: return
    if msg.sender_chat and msg.sender_chat.id == chat.id: return 

    await db_layer.register_chat(chat.id, chat.title)
    
    if lockdown_state[chat.id]:
        try: await context.bot.delete_message(chat.id, msg.message_id)
        except TelegramError: pass
        return

    # Whitelist & Admin bypass
    if await is_chat_admin(context.bot, chat.id, user.id) or await db_layer.is_whitelisted(chat.id, user.id): return

    raw_payload_text = msg.text or msg.caption or ""
    filename = msg.document.file_name if msg.document else ""
    
    if (msg.voice or msg.audio) and groq_2:
        audio_target = msg.voice if msg.voice else msg.audio
        try:
            tg_file = await context.bot.get_file(audio_target.file_id)
            temp_audio_path = f"voice_{audio_target.file_unique_id}.ogg"
            await tg_file.download_to_drive(temp_audio_path)
            with open(temp_audio_path, "rb") as audio_file:
                transcription = await groq_2.audio.transcriptions.create(model="whisper-large-v3", file=audio_file)
            raw_payload_text = transcription.text
            if os.path.exists(temp_audio_path): os.remove(temp_audio_path)
        except Exception: pass

    media_unique_id = msg.photo[-1].file_unique_id if msg.photo else msg.video.file_unique_id if msg.video else msg.document.file_unique_id if msg.document else None
    username = f"@{user.username}" if user.username else user.first_name
    reputation, total_messages = await db_layer.update_user_reputation(chat.id, user.id, 0.0)
    trust_score, age_risk = BehavioralProfiler.calculate_account_trust_score(user.id, total_messages, reputation)
    threat_multiplier = calculate_adaptive_threat_factor(chat.id)

    if media_unique_id:
        media_type = "photo" if msg.photo else "video" if msg.video else "document"
        incident_count = await db_layer.check_duplicate_media_hash(chat.id, media_unique_id, media_type)
        if incident_count > 3 and trust_score < 75.0:
            await db_layer.update_user_reputation(chat.id, user.id, -20.0)
            return await execute_local_punishment(context, chat.id, user.id, msg.message_id, "Coordinated Mass Media Duplicate Campaign Trigger", username, immediate_ban=True)

    if filename:
        file_alert, is_malicious = InfrastructureInspector.inspect_file_structure(filename)
        if is_malicious:
            await db_layer.update_user_reputation(chat.id, user.id, -40.0)
            return await execute_local_punishment(context, chat.id, user.id, msg.message_id, file_alert, username, immediate_ban=True)

    cleaned_text, entropy, mixed_scripts = UnicodeObfuscationEngine.deep_clean_and_normalize(raw_payload_text)
    
    if mixed_scripts >= 2 and len(raw_payload_text) < 350 and trust_score < 60.0:
         return await execute_local_punishment(context, chat.id, user.id, msg.message_id, f"Homoglyph Obfuscation Payload ({mixed_scripts} scripts mixed)", username)
    if entropy > 5.2 and len(cleaned_text) > 20 and len(raw_payload_text) < 350 and trust_score < 50.0:
         return await execute_local_punishment(context, chat.id, user.id, msg.message_id, f"High Entropy Randomized Bypass Match", username)

    # --- UPGRADED PROFANITY CHECK (regex + root-skeleton + fuzzy, all in one call) ---
    if rule_based_profanity_check(cleaned_text) or rule_based_profanity_check(raw_payload_text):
        await db_layer.update_user_reputation(chat.id, user.id, -10.0)
        return await execute_local_punishment(context, chat.id, user.id, msg.message_id, "Profanity / Group Policy Abuse Violation", username)
        
    if SCAM_KEYWORDS.search(cleaned_text) or SCAM_KEYWORDS.search(raw_payload_text):
        await db_layer.update_user_reputation(chat.id, user.id, -35.0)
        return await execute_local_punishment(context, chat.id, user.id, msg.message_id, "Deceptive Phishing Payload Vector", username, immediate_ban=True)

    url_alert, url_flagged = await InfrastructureInspector.resolve_and_profile_url(raw_payload_text)
    if url_flagged:
        await db_layer.update_user_reputation(chat.id, user.id, -15.0)
        return await execute_local_punishment(context, chat.id, user.id, msg.message_id, url_alert, username)

    is_bot_pattern = BehavioralProfiler.analyze_structural_velocity(chat.id, user.id, raw_payload_text)
    if is_bot_pattern and trust_score < 65.0:
        return await execute_local_punishment(context, chat.id, user.id, msg.message_id, "Behavioral Fingerprint Machine Burst Detection", username, immediate_ban=True)

    now = time.time()
    flood_cache[chat.id][user.id].append(now)

    if detect_coordinated_spam(chat.id, user.id):
        if not lockdown_state[chat.id]:
            lockdown_state[chat.id] = True
            await db_layer.persist_lockdown(chat.id, 1, "Coordinated spam attack detected", int(time.time())+600)
            await context.bot.set_chat_permissions(chat.id, ChatPermissions(can_send_messages=False))
            await context.bot.send_message(chat.id, "🚨 <b>Coordinated spam attack detected. Group locked for 10 minutes.</b>", parse_mode=ParseMode.HTML)
            asyncio.create_task(lockdown_expiry_timer(context.bot, chat.id, 600))
            return

    if len([t for t in flood_cache[chat.id][user.id] if now - t < 4.0]) >= 5:
        return await execute_local_punishment(context, chat.id, user.id, msg.message_id, "Text Burst Rapid Velocity Trigger", username, immediate_ban=True)

    has_bypass_symbols = bool(re.search(r'[^a-zA-Z0-9\s\u0900-\u097F]', raw_payload_text))
    has_scam_context = any(w in cleaned_text for w in ["crypto", "earn", "join", "channel", "airdrop", "free", "gift", "money", "invest"])
    is_untrusted = trust_score < 55.0
    
    if has_bypass_symbols or has_scam_context or is_untrusted or threat_multiplier > 1.5:
        if len(raw_payload_text.strip()) < 3: return
        
        if HF_API_KEY:
            hf_results = await asyncio.gather(
                check_tier2_2_hf_toxic_bert(raw_payload_text),
                check_hf_multilingual(raw_payload_text),
                check_hf_hindi_hate_speech(raw_payload_text),
                return_exceptions=True
            )
            if hf_results[0] is True:
                await db_layer.update_user_reputation(chat.id, user.id, -15.0)
                return await execute_local_punishment(context, chat.id, user.id, msg.message_id, "Pattern Toxicity Guard Violation (HF)", username)
            if hf_results[1] is True:
                await db_layer.update_user_reputation(chat.id, user.id, -20.0)
                return await execute_local_punishment(context, chat.id, user.id, msg.message_id, "Multilingual Hate Speech Guard Violation (HF)", username)
            if hf_results[2] is True:
                await db_layer.update_user_reputation(chat.id, user.id, -15.0)
                return await execute_local_punishment(context, chat.id, user.id, msg.message_id, "Hindi/Hinglish Hate Speech Guard Violation (HF)", username)

        # MAIN TASK MODERATION -> Uses groq_client (API Key 1)
        if groq_client and len(raw_payload_text.strip()) > 8:
            ai_res = await evaluate_via_groq(raw_payload_text)
            if ai_res.get("violation") and ai_res.get("confidence", 0) >= 80:
                action = ai_res.get("action", "ban")
                reason = f"Autonomous AI Defense Framework Flagged: {ai_res.get('reason')}"
                await db_layer.update_user_reputation(chat.id, user.id, -50.0)
                try: await context.bot.delete_message(chat.id, msg.message_id)
                except TelegramError: pass
                
                if action == "ban":
                    await context.bot.ban_chat_member(chat.id, user_id=user.id)
                    await db_layer.log_action(chat.id, user.id, 0, "AI_AUTONOMOUS_BAN", reason)
                    await context.bot.send_message(chat.id, f"🛑 <b>Autonomous AI Defense Network Ban</b>\n<b>User:</b> {username}\n<b>Reason:</b> {reason}", parse_mode=ParseMode.HTML)
                elif action == "mute":
                    until = int(time.time()) + 7200
                    await context.bot.restrict_chat_member(chat.id, user.id, permissions=ChatPermissions(can_send_messages=False), until_date=until)
                    await db_layer.log_action(chat.id, user.id, 0, "AI_AUTONOMOUS_MUTE", reason)
                    await context.bot.send_message(chat.id, f"🔇 <b>Autonomous AI Defense Network Mute (2 Hours)</b>\n<b>User:</b> {username}\n<b>Reason:</b> {reason}", parse_mode=ParseMode.HTML)

# ------------------------------------------------------------------
# SYSTEM GATEKEEPERS
# ------------------------------------------------------------------
async def gatekeeper_join_handler(update: Update, context: ContextTypes.DEFAULT_TYPE):
    chat = update.effective_chat
    if not update.message or not update.message.new_chat_members: return
    now = time.time()
    await db_layer.register_chat(chat.id, chat.title)
    
    new_humans = [m for m in update.message.new_chat_members if not m.is_bot]
    if not new_humans: return

    join_cache[chat.id].extend([now] * len(new_humans))
    recent_joins = [t for t in join_cache[chat.id] if now - t < 10.0]
    join_cache[chat.id] = recent_joins
    
    if len(recent_joins) > 6:
        lockdown_state[chat.id] = True
        await db_layer.persist_lockdown(chat.id, 1, "Automated Raid Matrix Shield Activation", int(time.time())+900)
        await context.bot.set_chat_permissions(chat.id, ChatPermissions(can_send_messages=False, can_send_media_messages=False))
        await context.bot.send_message(chat.id, "🚨 <b>Coordinated Raid Vector Detected.</b> Entering high security lockdown mode. Channels sealed.", parse_mode=ParseMode.HTML)
        for h in new_humans: 
            try: await context.bot.ban_chat_member(chat.id, h.id)
            except TelegramError: pass
        return

    for human in new_humans:
        if await db_layer.is_whitelisted(chat.id, human.id): continue
        try:
            await context.bot.restrict_chat_member(chat.id, human.id, permissions=ChatPermissions(can_send_messages=False))
            kb = [[InlineKeyboardButton("🔒 Pass Identity Gate", callback_data=f"gate_{human.id}")]]
            out = await context.bot.send_message(chat.id, f"🛡️ <b>Security Verification Protocol Required.</b>\n<b>User:</b> {human.first_name}\nComplete registration challenge within 60s.", reply_markup=InlineKeyboardMarkup(kb), parse_mode=ParseMode.HTML)
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
    if user_id != target_id: return await query.answer("❌ Verification access denied.", show_alert=True)
    if chat_id in captcha_registry and user_id in captcha_registry[chat_id]:
        try:
            full_perms = ChatPermissions(can_send_messages=True, can_send_audios=True, can_send_documents=True, can_send_photos=True, can_send_videos=True, can_send_other_messages=True, can_add_web_page_previews=True)
            await context.bot.restrict_chat_member(chat_id, user_id, permissions=full_perms)
            await context.bot.delete_message(chat_id, query.message.message_id)
            await query.answer("Verification Challenge Cleared. Identity Authenticated.", show_alert=True)
            await db_layer.update_user_reputation(chat_id, user_id, 5.0)
        except TelegramError: pass
        finally:
            await db_layer.persist_captcha(chat_id, user_id, query.message.message_id, 0, remove=True)
            captcha_registry[chat_id].pop(user_id, None)

async def analytics_command_handler(update: Update, context: ContextTypes.DEFAULT_TYPE):
    chat, user = update.effective_chat, update.effective_user
    if not chat or not user or not await is_chat_admin(context.bot, chat.id, user.id): return
    stats = await db_layer.get_chat_analytics_summary(chat.id)
    stress_level = calculate_adaptive_threat_factor(chat.id)
    report = (
        f"📊 <b>System Threat Analytics Report</b>\n"
        f"━━━━━━━━━━━━━━━━━━━━\n"
        f"• <b>Active Monitored Channel ID:</b> <code>{chat.id}</code>\n"
        f"• <b>Total Flagged Matrix Incidents:</b> <code>{stats.get('total_incidents', 0)}</code>\n"
        f"• <b>Autonomous Permanent Bans:</b> <code>{stats.get('bans', 0)}</code>\n"
        f"• <b>High-Risk Profiles Suspended:</b> <code>{stats.get('suspicious_users', 0)}</code>\n"
        f"• <b>Current Network Traffic Stress:</b> <code>{stress_level:.2f}x</code>\n"
        f"• <b>Global Firewall Status:</b> <code>HYBRID DB Active</code>\n"
    )
    await update.message.reply_text(report, parse_mode=ParseMode.HTML)

# ------------------------------------------------------------------
# DAILY ENGAGEMENT TRAILER ENGINE (USES GROQ 2 API)
# ------------------------------------------------------------------
async def phantom_daily_engagement_loop(bot: telegram.Bot):
    """Runs a background loop that broadcasts an engaging cyber status roast once a day using GROQ 2."""
    while True:
        await asyncio.sleep(86400) # Sleep exactly 24 hours between status engagement strikes
        logger.info("📡 Initializing Automated Daily Phantom Engagement Sequence across nodes...")
        managed_nodes = await db_layer.get_all_managed_chats()
        if not managed_nodes: continue
            
        for chat_id in managed_nodes:
            try:
                stats = await db_layer.get_chat_analytics_summary(chat_id)
                broadcast_content = "⚠️ <b>| PHANTOM DELUXE DAILY SYSTEM DIAGNOSTIC |</b>\n\n"
                
                # STRICT REQUIREMENT: Only uses groq_2 (GROQ_API_KEY_2) for the trailer.
                if groq_2:
                    try:
                        raw_prompt = (
                            f"Generate a witty, edgy, cyberpunk security diagnostic broadcast for a Telegram group chat. "
                            f"The bot's name is Phantom Deluxe. Mention we caught {stats.get('total_incidents', 0)} data leaks/scams today "
                            f"and threw {stats.get('bans', 0)} spammers out the airlock. Keep it funny, engaging, sarcastic, "
                            f"and write in smooth, urban English. No long preambles, exactly 3 lines."
                        )
                        res = await groq_2.chat.completions.create(
                            model=GROQ_MODEL,
                            messages=[{"role": "user", "content": raw_prompt}],
                            max_tokens=200,
                            temperature=0.8
                        )
                        broadcast_content += f"📡 <code>Incoming transmission...</code>\n\n<i>\"{res.choices[0].message.content.strip()}\"</i>"
                    except Exception as e:
                        logger.error(f"Daily Engine Groq2 Error: {e}")
                        broadcast_content += "🤖 <b>Matrix Status:</b> Secure.\nNo vulnerabilities leaked today. Keep the conversation clean, or the firewall will select you next."
                else:
                    broadcast_content += "🤖 <b>Matrix Status:</b> Secure.\nNo vulnerabilities leaked today. Keep the conversation clean, or the firewall will select you next."
                
                await bot.send_message(chat_id, broadcast_content, parse_mode=ParseMode.HTML)
                await asyncio.sleep(1.0)
            except TelegramError: pass

# ------------------------------------------------------------------
# TIMEOUTS, REAPERS & UTILITIES
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
            if row and row[0] == target_msg_id: await execute_direct_unban_eviction(bot, chat_id, user_id, target_msg_id)

async def lift_lockdown_directly(bot: telegram.Bot, chat_id: int):
    lockdown_state[chat_id] = False
    await db_layer.persist_lockdown(chat_id, 0, "", 0)
    try:
        full = ChatPermissions(can_send_messages=True, can_send_audios=True, can_send_documents=True, can_send_photos=True, can_send_videos=True, can_send_other_messages=True, can_add_web_page_previews=True)
        await bot.set_chat_permissions(chat_id, full)
        await bot.send_message(chat_id, "🔓 <b>Lockdown Cleared.</b> Firewall parameters normal.", parse_mode=ParseMode.HTML)
    except TelegramError: pass

async def lockdown_expiry_timer(bot: telegram.Bot, chat_id: int, wait_duration: float):
    await asyncio.sleep(wait_duration)
    if lockdown_state[chat_id]: await lift_lockdown_directly(bot, chat_id)

async def execute_recovery_synchronization(app: Application):
    now = int(time.time())
    async with aiosqlite.connect(db_layer.db_path) as db:
        async with db.execute("SELECT chat_id, expires_at, reason FROM lockdown_state WHERE active = 1") as cursor: lockdowns = await cursor.fetchall()
    for chat_id, expires_at, reason in lockdowns:
        if expires_at <= now: await lift_lockdown_directly(app.bot, chat_id)
        else:
            lockdown_state[chat_id] = True
            asyncio.create_task(lockdown_expiry_timer(app.bot, chat_id, float(expires_at - now)))
    async with aiosqlite.connect(db_layer.db_path) as db:
        async with db.execute("SELECT chat_id, user_id, message_id, expires_at FROM captcha_registry") as cursor: captchas = await cursor.fetchall()
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
            for cid in list(flood_cache.keys()):
                for uid in list(flood_cache[cid].keys()):
                    flood_cache[cid][uid] = [t for t in flood_cache[cid][uid] if now - t < 30]
                    if not flood_cache[cid][uid]: del flood_cache[cid][uid]
                if not flood_cache[cid]: del flood_cache[cid]
            for cid in list(behavioral_velocity_cache.keys()):
                for uid in list(behavioral_velocity_cache[cid].keys()):
                    behavioral_velocity_cache[cid][uid] = [t for t in behavioral_velocity_cache[cid][uid] if now - t[0] < 30]
                    if not behavioral_velocity_cache[cid][uid]: del behavioral_velocity_cache[cid][uid]
                if not behavioral_velocity_cache[cid]: del behavioral_velocity_cache[cid]
        except Exception: pass

async def execute_local_punishment(context: ContextTypes.DEFAULT_TYPE, chat_id: int, user_id: int, msg_id: int, reason: str, username: str, immediate_ban: bool = False):
    try:
        bot_member = await context.bot.get_chat_member(chat_id, context.bot.id)
        if not can_delete_messages(bot_member): return
    except TelegramError: return

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
        card_content = (
            f"⚠️ <b>| PHANTOM DELUXE SECURITY BREACH |</b>\n"
            f"━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n"
            f"🚫 <b>Target Profile:</b> {username}\n"
            f"🛡️ <b>System Verdict:</b> FIRST WARNING STRIKE\n"
            f"⚙️ <b>Breached Vector:</b> <code>{reason}</code>\n"
            f"📊 <b>Active Incident Threshold:</b> <code>{warnings}/2</code>\n"
            f"━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n"
            f"❗ <i>Notice: Phantom Matrix is watching you. Next strike issues an automated permanent termination.</i>"
        )
        await context.bot.send_message(chat_id, card_content, parse_mode=ParseMode.HTML)

        if EDGE_TTS_AVAILABLE:
            try:
                clean_name = re.sub(r'[<&>"\']', '', username.replace("@", "")) or "User"
                tts_text = f"Halt, {clean_name}! You are now on the radar of the Phantom Deluxe Security Matrix. Do not violate the group protocols again. This is your first warning strike. Next time, it is an immediate permanent termination. Game over."
                temp_mp3_path = f"warn_{user_id}_{int(time.time())}.mp3"
                audio_generated = False
                try:
                    communicate = edge_tts.Communicate(tts_text, "en-US-BrianNeural")
                    await communicate.save(temp_mp3_path)
                    audio_generated = True
                except Exception:
                    try:
                        communicate = edge_tts.Communicate(tts_text, "en-GB-RyanNeural")
                        await communicate.save(temp_mp3_path)
                        audio_generated = True
                    except Exception: pass

                if audio_generated and os.path.exists(temp_mp3_path):
                    with open(temp_mp3_path, "rb") as audio_file:
                        await context.bot.send_audio(chat_id=chat_id, audio=audio_file, title="👁️ Phantom Deluxe Strike", performer="Phantom Network Core", caption=f"⚡ Phantom Warning Protocol deployed for {username}!")
                    if os.path.exists(temp_mp3_path): os.remove(temp_mp3_path)
            except Exception: pass
    else:
        try:
            await context.bot.ban_chat_member(chat_id, user_id)
            await db_layer.log_action(chat_id, user_id, 0, "BAN", reason)
            await db_layer.reset_warnings_atomic(chat_id, user_id)
            ban_content = f"🛑 <b>| PERMANENT RADICAL BAN ESCALATION |</b>\n━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n👤 <b>Evicted User:</b> {username}\n❌ <b>Reason:</b> {reason} (Warning Limits Exhausted)\n📉 <b>Status:</b> Terminated from Channel Node."
            await context.bot.send_message(chat_id, ban_content, parse_mode=ParseMode.HTML)
        except TelegramError: pass

async def evaluate_via_groq(text: str) -> dict:
    if not groq_client: return {"violation": False, "action": "ignore"}
    prompt = "You are an automated chat defense filter. Check this text for advanced stealth scams, hacking exploits, raid setups, or malicious intent across mixed Hindi/English text. Respond ONLY with a standard raw JSON structure: {'violation': true/false, 'action': 'ban'/'mute'/'ignore', 'confidence': 0-100, 'reason': 'summary'}"
    try:
        res = await groq_client.chat.completions.create(model=GROQ_MODEL, response_format={"type": "json_object"}, messages=[{"role": "system", "content": prompt}, {"role": "user", "content": text}], max_tokens=120, temperature=0.0)
        return json.loads(res.choices[0].message.content)
    except Exception: return {"violation": False, "action": "ignore"}

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
    
    # 💥 Launching the Daily Attention Grabber explicitly using GROQ 2
    asyncio.create_task(phantom_daily_engagement_loop(app.bot))
    
    logger.info("🛡️ Production Security Firewall Matrix Fully Deployed and Active.")

def main():
    if not TELEGRAM_BOT_TOKEN: 
        logger.error("Bhai, TELEGRAM_BOT_TOKEN missing hai!")
        return
        
    app = Application.builder().token(TELEGRAM_BOT_TOKEN).post_init(post_startup_validation).build()
    
    app.add_handler(CommandHandler("start", start_command_handler))
    app.add_handler(CommandHandler("analytics", analytics_command_handler))
    app.add_handler(CommandHandler("add_white", add_white_command))
    app.add_handler(CommandHandler("remove_white", remove_white_command))
    app.add_handler(CommandHandler("whitelist", whitelist_command_handler))
    
    app.add_handler(CallbackQueryHandler(process_gate_callback, pattern=r"^gate_"))
    app.add_handler(MessageHandler(filters.StatusUpdate.NEW_CHAT_MEMBERS, gatekeeper_join_handler))
    app.add_handler(MessageHandler(filters.TEXT | filters.COMMAND | filters.PHOTO | filters.VIDEO | filters.Document.ALL | filters.VOICE | filters.AUDIO, ingestion_pipeline))
    
    if WEBHOOK_URL:
        logger.info(f"🛡️ Launching Webhook Core Layer on port {PORT}...")
        app.run_webhook(listen="0.0.0.0", port=PORT, url_path=TELEGRAM_BOT_TOKEN, webhook_url=f"{WEBHOOK_URL}/{TELEGRAM_BOT_TOKEN}")
    else:
        logger.info("🛡️ Launching Polling Engine Layer...")
        app.run_polling(allowed_updates=Update.ALL_TYPES)

if __name__ == "__main__":
    main()
