import sqlite3
import os
from dotenv import load_dotenv

load_dotenv()  

DB = os.getenv("DB")  


def init_db():
    conn = sqlite3.connect(DB)
    c = conn.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS liquidity_pools
                 (id INTEGER PRIMARY KEY, token1 TEXT, token2 TEXT, reserve1 REAL, reserve2 REAL)''')
    c.execute('''CREATE TABLE IF NOT EXISTS supported_tokens
                 (id INTEGER PRIMARY KEY, symbol TEXT UNIQUE, name TEXT)''')
 
    c.execute('''CREATE TABLE IF NOT EXISTS cross_chain_transactions
             (id TEXT PRIMARY KEY, user_id INTEGER, token_from TEXT, token_to TEXT, amount REAL, source_chain TEXT, target_chain TEXT, status TEXT, created_at INTEGER, completed_at INTEGER)''')
    c.execute('''CREATE TABLE IF NOT EXISTS proposals
             (id INTEGER PRIMARY KEY, title TEXT, description TEXT, created_by INTEGER, created_at INTEGER, status TEXT DEFAULT 'open')''')
    c.execute('''CREATE TABLE IF NOT EXISTS votes
             (id INTEGER PRIMARY KEY, proposal_id INTEGER, user_id INTEGER, vote TEXT, weight REAL)''')
    c.execute('''CREATE TABLE IF NOT EXISTS dao_rewards
             (id INTEGER PRIMARY KEY, user_id INTEGER, reward REAL DEFAULT 0)''')
             
    conn.commit()
    conn.close()

def initialize_all_tables():
    # Creates all the tables
    conn = sqlite3.connect(DB)
    c = conn.cursor()
    # Create users table
    c.execute('''CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE,
        wallet TEXT,
        password TEXT,
        email TEXT UNIQUE,
        preferences TEXT,
        balance INTEGER DEFAULT 0
    )''')
    c.execute("UPDATE users SET balance = 0 WHERE balance IS NULL")

    # Create posts table
    c.execute('''CREATE TABLE IF NOT EXISTS posts (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        title TEXT,
        description TEXT,
        token TEXT
    )''')

    # Create liquidity_pools table
    c.execute('''CREATE TABLE IF NOT EXISTS liquidity_pools (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        token1 TEXT,
        token2 TEXT,
        reserve1 REAL,
        reserve2 REAL
    )''')

    # Create supported_tokens table
    c.execute('''CREATE TABLE IF NOT EXISTS supported_tokens (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        symbol TEXT UNIQUE,
        name TEXT
    )''')

    # Create cross_chain_transactions table
    c.execute('''CREATE TABLE IF NOT EXISTS cross_chain_transactions (
        id TEXT PRIMARY KEY,
        user_id INTEGER,
        token_from TEXT,
        token_to TEXT,
        amount REAL,
        source_chain TEXT,
        target_chain TEXT,
        status TEXT,
        created_at INTEGER,
        completed_at INTEGER
    )''')

    # Create proposals table
    c.execute('''CREATE TABLE IF NOT EXISTS proposals (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        title TEXT,
        description TEXT,
        created_by INTEGER,
        created_at INTEGER,
        status TEXT DEFAULT 'open'
    )''')

    # Create votes table
    c.execute('''CREATE TABLE IF NOT EXISTS votes (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        proposal_id INTEGER,
        user_id INTEGER,
        vote TEXT,
        weight REAL
    )''')

    # Create dao_rewards table
    c.execute('''CREATE TABLE IF NOT EXISTS dao_rewards (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER,
        reward REAL DEFAULT 0
    )''')

    # Create message_media table
    c.execute('''CREATE TABLE IF NOT EXISTS message_media (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        message_id INTEGER,
        media_type TEXT,
        media_url TEXT
    )''')

    conn.commit()
    conn.close()
