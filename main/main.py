from flask import Flask, render_template, request, jsonify
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Cipher import AES
from argon2 import PasswordHasher
from config import setup_caching, setup_static_files
from dotenv import load_dotenv 
from utils import init_db, initialize_all_tables
from flask_socketio import SocketIO, emit
from web3 import Web3
from utils import init_db, initialize_all_tables
import base64
import sqlite3 
import hashlib
import json
import os
import jwt
import uuid 
import datetime 

load_dotenv() 

app = Flask(__name__)

SECRET_KEY = os.getenv("SECRET_KEY")
app.config['SECRET_KEY'] = SECRET_KEY
DB = os.getenv("DB")
socketio = SocketIO(app)
INFURA_URL = os.getenv("INFURA_URL")
w3 = Web3(Web3.HTTPProvider(INFURA_URL))


def create_token(user_id):
    payload = {
        "user_id": user_id,
        "exp": datetime.datetime.utcnow() + datetime.timedelta(hours=24)  
    }
    token = jwt.encode(payload, SECRET_KEY, algorithm="HS256")
    return token
def verify_token(token):
    try: 
        decoded = jwt.decode(token, SECRET_KEY, algorithms=["HS256"])
        print("Decoded token:", decoded)
        return decoded.get('user_id')  
    except jwt.ExpiredSignatureError:
        print("Token has been expired") 
        return jsonify({"message": "expired token"})
    except jwt.InvalidTokenError as e:
        print(f"Invalid token : {e}")
        return jsonify({"message": "Invalid token"})
@app.after_request
def add_header(response):
    return setup_caching(response)

@app.route('/static/<path:filename>')
def static_files(filename):
    return setup_static_files(filename)

#  pages 
@app.route('/')
def home():
    return render_template("Home.html")

ph = PasswordHasher()
def hash_password(password):
    return ph.hash(password)
def verify_password(hashed_password, password): 
    try:
        return ph.verify(hashed_password, password)
    except Exception as e:
        print(f"Password verification error: {e}")
        return jsonify({"message " : "error occurred"}) , 500


@app.route('/register', methods=['POST'])
def register():
    try:
        data = request.get_json()
        username = data.get('username')
        wallet = data.get('wallet')
        password = data.get('password')
        email = data.get('email')

        if not all([username, wallet, password, email]):
            return jsonify({'message': 'Missing fields'}), 400

        hashed = hash_password(password)
        print(f"Password hashed: {hashed}")  

        conn = sqlite3.connect(DB)
        c = conn.cursor()
        c.execute("""
            INSERT INTO users (username, wallet, password, email, preferences) 
            VALUES (?, ?, ?, ?, ?)
        """, (username, wallet, hashed, email, '{}'))
        conn.commit()
        conn.close()
        return jsonify({'message': 'User registered'}), 201
    except sqlite3.IntegrityError as e:
        print(f"IntegrityError: {e}")  
        return jsonify({'message': 'User already exits or internal server error'}), 400
    except Exception as e:
        print(f"Error: {e}")  
        return jsonify({'message': 'Internal server error'}), 500

@app.route('/login', methods=['POST'])
def login():
    try:
        data = request.get_json()
        username = data.get('username')
        password = data.get('password')
        if not all([username, password]):
            return jsonify({'message': 'Missing fields'}), 400
        conn = sqlite3.connect(DB)
        c = conn.cursor()
        c.execute("SELECT id, password FROM users WHERE username = ?", (username,))
        user = c.fetchone()
        conn.close()

        if user:
            print("User found:", user)   
            if verify_password(user[1], password):
                token = create_token(user[0])
                return jsonify({'login successfull ,token': token}), 200
            else:
                print("Password verification failed.")  
                return jsonify({'message': 'Invalid credentials or an error occurred'}), 401

        print("User not found in the database.")  
        return jsonify({'message': 'Invalid credentials'}), 401

    except Exception as e:
        print(f"Error occurred: {e}")  
        return jsonify({'message': 'Internal server error'}), 500
      


@app.route('/reset-password', methods=['POST'])
def reset_password():
    data = request.get_json()
    token = data.get('token')
    new_password = data.get('new_password')
    if not all([token, new_password]):
        return jsonify({'message': 'Missing fields'}), 400
    user_id = verify_token(token)
    if not user_id:
        return jsonify({'message': 'Invalid or expired token'}), 400
    hashed = hash_password(new_password)
    conn = sqlite3.connect(DB)
    c = conn.cursor()
    c.execute("UPDATE users SET password = ? WHERE id = ?", (hashed, user_id))
    conn.commit()
    conn.close()
    return jsonify({'message': 'Password updated'}), 200


@app.route('/prfl', methods=['GET', 'PUT'])
def profile():
    try:
        token = request.headers.get('Authorization')
        if not token:
            return jsonify({'message': 'Token required'}), 401

        user_id = verify_token(token)
        if not user_id:
            return jsonify({'message': 'Invalid token'}), 401

        conn = sqlite3.connect(DB)
        c = conn.cursor()

        if request.method == 'GET':
            c.execute("SELECT username, wallet, email, preferences, balance FROM users WHERE id = ?", (user_id,))
            user = c.fetchone()
            conn.close()
            
            if user:
                 eth_address = user[1]
                 token_balances = {}
                 if eth_addres:
                    token_balances['bitcoin'] = get_eth_balance(eth_address)
                    token_balances['ethereum'] = get_eth_balance(eth_address)
                    token_balances['solana'] = get_eth_balance(eth_address)
                 else:
                    token_balances['bitcoin'] = 0
                    token_balances['ethereum'] = 0
                    token_balances['solana'] = 0
                 return jsonify({
                    'username': user[0],
                    'wallet': user[1],
                    'email': user[2],
                    'preferences': json.loads(user[3]) if user[3] else {},
                    'balance': user[4],
                    'token_balances': token_balances
                 }), 200
                
            return jsonify({'message': 'User not found'}), 404
    except Exception as e:
         return jsonify({'message': 'Internal server error'}), 500



def get_eth_balance(address):
    try:
        balance_wei = w3.eth.get_balance(address)
        balance_eth = w3.from_wei(balance_wei, 'ether')
        return balance_eth
    except:
        return 0
      
@app.route('/connect-wallet', methods=['POST'])
def connect_wallet():
    token = request.headers.get('Authorization')
    if not token:
        return jsonify({'message': 'Token required'}), 401
    user_id = verify_token(token)
    if not user_id:
        return jsonify({'message': 'Invalid token or user id not defined'}), 401
    data = request.get_json()
    if not data or 'wallet_address' not in data:
       return jsonify({'message': 'Missing wallet_address'}), 400
    wallet_address = data['wallet_address']
    if not wallet_address.startswith("0x") or len(wallet_address) != 42:
       return jsonify({'message': 'Invalid wallet_address format'}), 400
    conn = sqlite3.connect(DB)
    c = conn.cursor()
    c.execute("UPDATE users SET wallet = ? WHERE id = ?", (wallet_address, user_id))
    conn.commit()
    conn.close()
    return jsonify({'message': 'Wallet connected'}), 200


    
@app.route('/deposit', methods=['POST'])
def deposit():
    try:
        token = request.headers.get('Authorization')
        print("Token received:", token)
        user_id = verify_token(token)
        print("User ID:", user_id)
        if not user_id:
            return jsonify({'message': 'Invalid token or user ID not defined'}), 401
        data = request.get_json()
        print("Received Data:", data)
        amount = data.get('amount')
        print("Amount to deposit:", amount)
        if not amount or not isinstance(amount, (int, float)) or amount <= 0:
            return jsonify({'message': 'Invalid amount'}), 400
        conn = sqlite3.connect(DB)
        c = conn.cursor()
        print("Database connected")
        c.execute("SELECT balance FROM users WHERE id = ?", (user_id,))
        result = c.fetchone()
        if not result:
            return jsonify({'message': 'User not found'}), 404
        balance = result[0]
        print("Current balance:", balance)
        c.execute("UPDATE users SET balance = balance + ? WHERE id = ?", (amount, user_id))
        conn.commit()
        print("Balance updated successfully")
        c.execute("SELECT balance FROM users WHERE id = ?", (user_id,))
        updated_balance = c.fetchone()[0]
        print("Updated balance:", updated_balance)
        conn.close()
        return jsonify({'balance': updated_balance}), 200
    except Exception as e:
        print("Error occurred:", e)
        return jsonify({'message': 'Internal server error'}), 500

@app.route('/withdraw', methods=['POST'])
def withdraw():
    token = request.headers.get('Authorization')
    if not token:
        return jsonify({'message': 'Token required'}), 401
    user_id = verify_token(token)
    if not user_id:
        return jsonify({'message': 'Invalid token'}), 401
    data = request.get_json()
    amount = data.get('amount')
    if not amount or not isinstance(amount, (int, float)) or amount <= 0:
        return jsonify({'message': 'Invalid amount'}), 400
    conn = sqlite3.connect(DB)
    c = conn.cursor()
    c.execute("SELECT balance FROM users WHERE id = ?", (user_id,))
    balance = c.fetchone()[0]
    if balance < amount:
        conn.close()
        return jsonify({'message': 'Insufficient balance'}), 400
    c.execute("UPDATE users SET balance = balance - ? WHERE id = ?", (amount, user_id))
    conn.commit()
    c.execute("SELECT balance FROM users WHERE id = ?", (user_id,))
    new_balance = c.fetchone()[0]
    conn.close()
    return jsonify({'balance': new_balance}), 200

@app.route('/view-wallet-balances', methods=['GET'])
def view_wallet_balances():
    token = request.headers.get('Authorization')
    if not token:
        return jsonify({'message': 'Token required'}), 401
    user_id = verify_token(token)
    if not user_id:
        return jsonify({'message': 'Invalid token'}), 401
    conn = sqlite3.connect(DB)
    c = conn.cursor()
    c.execute("SELECT balance FROM users WHERE id = ?", (user_id,))
    balance = c.fetchone()
    conn.close()
    if balance:
        return jsonify({'balance': balance[0]}), 200
    return jsonify({'message': 'User not found'}), 404


SUPPORTED_TOKENS = ['TOKEN1', 'TOKEN2', 'TOKEN3']
PLATFORM_FEE_RATE = 0.003

@app.route('/swap', methods=['POST'])
def swap():
    try:
        
        token = request.headers.get('Authorization')
        print(f"Token received: {token}")  
        user_id = verify_token(token)
        if not user_id:
            return jsonify({'message': 'Invalid token'}), 401
        print(f"Token validated. User ID: {user_id}")  

        
        data = request.get_json()
        if not data:
            return jsonify({'message': 'Invalid request data'}), 400
        print(f"Request data: {data}")  

        token_from = data.get('token_from')
        token_to = data.get('token_to')
        amount = data.get('amount')
        print(f"Swap details - From: {token_from}, To: {token_to}, Amount: {amount}")  

      
        if not all([token_from, token_to, amount]) or not isinstance(amount, (int, float)) or amount <= 0:
            return jsonify({'message': 'Invalid input'}), 400

        
        conn = sqlite3.connect(DB)
        c = conn.cursor()
        c.execute("SELECT reserve1, reserve2 FROM liquidity_pools WHERE token1 = ? AND token2 = ?", (token_from, token_to))
        pool = c.fetchone()
        print(f"Liquidity pool: {pool}")  

        if not pool:
            return jsonify({'message': 'Liquidity pool not found'}), 404

        reserve1, reserve2 = pool
        print(f"Reserves - Token1: {reserve1}, Token2: {reserve2}")  

       
        c.execute("SELECT balance FROM user_balances WHERE user_id = ? AND token = ?", (user_id, token_from))
        user_balance = c.fetchone()
        print(f"User balance for {token_from}: {user_balance}")  

        if not user_balance or user_balance[0] < amount:
            return jsonify({'message': 'Insufficient balance'}), 400

        
        amount_with_fee = float(amount) * 0.997 
        swapped_amount = (amount_with_fee * reserve2) / (reserve1 + amount_with_fee)
        print(f"Amount after fee: {amount_with_fee}, Swapped amount: {swapped_amount}")  

        
        new_reserve1 = reserve1 + amount_with_fee
        new_reserve2 = reserve2 - swapped_amount
        new_user_balance_from = user_balance[0] - amount
        c.execute("UPDATE liquidity_pools SET reserve1 = ?, reserve2 = ? WHERE token1 = ? AND token2 = ?",
                  (new_reserve1, new_reserve2, token_from, token_to))
        c.execute("UPDATE user_balances SET balance = balance - ? WHERE user_id = ? AND token = ?",
                  (amount, user_id, token_from))
        c.execute("UPDATE user_balances SET balance = balance + ? WHERE user_id = ? AND token = ?",
                  (swapped_amount, user_id, token_to))
        conn.commit()
        print(f"Database updated successfully") 
        conn.close()
        return jsonify({'swapped_amount': swapped_amount}), 200
    except sqlite3.OperationalError as e:
        print(f"Database Error: {e}")  
        return jsonify({'message': 'Database error occurred'}), 500
    except Exception as e:
        print(f"Error occurred: {e}")  
        return jsonify({'message': 'Internal server error'}), 500


@app.route('/add-liquidity', methods=['POST'])
def add_liquidity():
    token1 = request.json.get('token1')
    token2 = request.json.get('token2')
    amount1 = request.json.get('amount1')
    amount2 = request.json.get('amount2')
    if token1 not in SUPPORTED_TOKENS or token2 not in SUPPORTED_TOKENS or token1 == token2:
        return jsonify({'message': 'Invalid tokens'}), 400
    if not all([amount1, amount2]) or not all(isinstance(a, (int, float)) and a > 0 for a in [amount1, amount2]):
        return jsonify({'message': 'Invalid amounts'}), 400
    token1_balance = get_user_token_balance(user_id, token1)
    token2_balance = get_user_token_balance(user_id, token2)
    if token1_balance < amount1 or token2_balance < amount2:
        return jsonify({'message': 'Insufficient balance'}), 400
    pool = get_pool(token1, token2)
    if pool:
        new_reserve1 = pool['reserve1'] + amount1
        new_reserve2 = pool['reserve2'] + amount2
        update_pool_reserves(pool['id'], new_reserve1, new_reserve2)
    else:
        create_pool(token1, token2, amount1, amount2)
    update_user_token_balance(user_id, token1, token1_balance - amount1)
    update_user_token_balance(user_id, token2, token2_balance - amount2)
    return jsonify({'message': 'Liquidity added'}), 200

def get_pool(token1, token2):
    conn = sqlite3.connect(DB)
    c = conn.cursor()
    c.execute("SELECT id, reserve1, reserve2 FROM liquidity_pools WHERE (token1 = ? AND token2 = ?) OR (token1 = ? AND token2 = ?)", (token1, token2, token2, token1))
    pool = c.fetchone()
    conn.close()
    if pool:
        return {'id': pool[0], 'reserve1': pool[1], 'reserve2': pool[2]}
    return None

def create_pool(token1, token2, reserve1, reserve2):
    conn = sqlite3.connect(DB)
    c = conn.cursor()
    c.execute("INSERT INTO liquidity_pools (token1, token2, reserve1, reserve2) VALUES (?, ?, ?, ?)", (token1, token2, reserve1, reserve2))
    conn.commit()
    conn.close()

def update_pool_reserves(pool_id, reserve1, reserve2):
    conn = sqlite3.connect(DB)
    c = conn.cursor()
    c.execute("UPDATE liquidity_pools SET reserve1 = ?, reserve2 = ? WHERE id = ?", (reserve1, reserve2, pool_id))
    conn.commit()
    conn.close()

@app.route('/cross-swap', methods=['POST'])
def cross_swap():
    token_from = request.json.get('token_from')
    token_to = request.json.get('token_to')
    amount = request.json.get('amount')
    source_chain = request.json.get('source_chain')
    target_chain = request.json.get('target_chain')
    if token_from not in SUPPORTED_TOKENS or token_to not in SUPPORTED_TOKENS or token_from == token_to:
        return jsonify({'message': 'Invalid tokens'}), 400
    if not all([amount, source_chain, target_chain]) or not isinstance(amount, (int, float)) or amount <= 0:
        return jsonify({'message': 'Invalid data'}), 400
    user_id = verify_token(request.headers.get('Authorization'))
    if not user_id:
        return jsonify({'message': 'Invalid token'}), 401
    token_from_balance = get_user_token_balance(user_id, token_from)
    if token_from_balance < amount:
        return jsonify({'message': 'Insufficient balance'}), 400
    transaction_id = str(uuid.uuid4())
    conn = sqlite3.connect(DB)
    c = conn.cursor()
    c.execute("INSERT INTO cross_chain_transactions (id, user_id, token_from, token_to, amount, source_chain, target_chain, status, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
              (transaction_id, user_id, token_from, token_to, amount, source_chain, target_chain, 'pending', int(time.time())))
    conn.commit()
    conn.close()
    update_user_token_balance(user_id, token_from, token_from_balance - amount)
    return jsonify({'transaction_id': transaction_id, 'status': 'pending'}), 200

app.route('/cross-swap/status/<transaction_id>', methods=['GET'])
def cross_swap_status(transaction_id):
    conn = sqlite3.connect(DB)
    c = conn.cursor()
    c.execute("SELECT status FROM cross_chain_transactions WHERE id = ?", (transaction_id,))
    transaction = c.fetchone()
    conn.close()
    if transaction:
        return jsonify({'transaction_id': transaction_id, 'status': transaction[0]}), 200
    return jsonify({'message': 'Transaction not found'}), 404

def process_cross_chain_transactions():
    conn = sqlite3.connect(DB)
    c = conn.cursor()
    c.execute("SELECT id, user_id, token_to, amount, target_chain FROM cross_chain_transactions WHERE status = 'pending'")
    transactions = c.fetchall()
    for tx in transactions:
        tx_id, user_id, token_to, amount, target_chain = tx
        token_to_balance = get_user_token_balance(user_id, token_to)
        update_user_token_balance(user_id, token_to, token_to_balance + amount)
        c.execute("UPDATE cross_chain_transactions SET status = 'completed', completed_at = ? WHERE id = ?", (int(time.time()), tx_id))
    conn.commit()
    conn.close()



def distribute_rewards():
    conn = sqlite3.connect(DB)
    c = conn.cursor()
    c.execute("SELECT user_id, liquidity_amount FROM liquidity_providers")
    providers = c.fetchall()
    for user_id, liquidity_amount in providers:
        reward = liquidity_amount * 0.001
        c.execute("UPDATE liquidity_providers SET rewards = rewards + ? WHERE user_id = ?", (reward, user_id))

@app.route('/proposals', methods=['POST'])
def create_proposal():
    try:
       
        token = request.headers.get('Authorization')
        if not token:
            return jsonify({'message': 'Token required'}), 401

        user_id = verify_token(token)
        if not user_id:
            return jsonify({'message': 'Invalid token'}), 401

        print(f"Token validated. User ID: {user_id}")  

        
        data = request.get_json()
        title = data.get('title')
        description = data.get('description')
        if not all([title, description]):
            return jsonify({'message': 'Missing fields: title and description are required.'}), 400

        print(f"Received Data - Title: {title}, Description: {description}")

        
        timestamp = int(datetime.datetime.now().timestamp())
        conn = sqlite3.connect(DB)
        c = conn.cursor()
        c.execute('''
            INSERT INTO proposals (title, description, created_by, created_at)
            VALUES (?, ?, ?, ?)
        ''', (title, description, user_id, timestamp))
        conn.commit()
        proposal_id = c.lastrowid
        conn.close()

        print(f"Proposal Created Successfully. ID: {proposal_id}")  
        return jsonify({'proposal_id': proposal_id, 'status': 'open'}), 201

    except sqlite3.OperationalError as e:
        print(f"Database Error: {e}")  
        return jsonify({'message': 'Database error occurred.'}), 500
    except Exception as e:
        print(f"Error occurred: {e}")  
        return jsonify({'message': 'Internal server error'}), 500

@app.route('/proposals/<int:proposal_id>/vote', methods=['POST'])
def vote_proposal(proposal_id):
    user_id = verify_token(request.headers.get('Authorization'))
    if not user_id:
        return jsonify({'message': 'Invalid token'}), 401
    data = request.get_json()
    vote = data.get('vote')
    if vote not in ['yes', 'no']:
        return jsonify({'message': 'Invalid vote'}), 400
    conn = sqlite3.connect(DB)
    c = conn.cursor()
    c.execute("SELECT status FROM proposals WHERE id = ?", (proposal_id,))
    proposal = c.fetchone()
    if not proposal or proposal[0] != 'open':
        conn.close()
        return jsonify({'message': 'Proposal not found or closed'}), 404
    c.execute("SELECT * FROM votes WHERE proposal_id = ? AND user_id = ?", (proposal_id, user_id))
    existing_vote = c.fetchone()
    if existing_vote:
        conn.close()
        return jsonify({'message': 'User has already voted'}), 400
    balance = get_user_token_balance(user_id, 'TOKEN1')
    if balance <= 0:
        conn.close()
        return jsonify({'message': 'No tokens to vote with'}), 400
    c.execute("INSERT INTO votes (proposal_id, user_id, vote, weight) VALUES (?, ?, ?, ?)", (proposal_id, user_id, vote, balance))
    conn.commit()
    conn.close()
    return jsonify({'message': 'Vote recorded'}), 200

@app.route('/proposals-vote', methods=['GET'])
def list_proposals():
    conn = sqlite3.connect(DB)
    c = conn.cursor()
    c.execute("SELECT id, title, description, created_by, created_at, status FROM proposals")
    proposals = c.fetchall()
    conn.close()
    proposal_list = []
    for p in proposals:
        proposal_list.append({
            'id': p[0],
            'title': p[1],
            'description': p[2],
            'created_by': p[3],
            'created_at': p[4],
            'status': p[5]
        })
    return jsonify({'proposals': proposal_list}), 200

@app.route('/proposals/<int:proposal_id>', methods=['GET'])
def view_proposal(proposal_id):
    conn = sqlite3.connect(DB)
    c = conn.cursor()
    c.execute("SELECT id, title, description, created_by, created_at, status FROM proposals WHERE id = ?", (proposal_id,))
    proposal = c.fetchone()
    if not proposal:
        conn.close()
        return jsonify({'message': 'Proposal not found'}), 404
    c.execute("SELECT vote, weight FROM votes WHERE proposal_id = ?", (proposal_id,))
    votes = c.fetchall()
    conn.close()
    vote_summary = {'yes': 0, 'no': 0}
    for v in votes:
        vote_summary[v[0]] += v[1]
    return jsonify({
        'id': proposal[0],
        'title': proposal[1],
        'description': proposal[2],
        'created_by': proposal[3],
        'created_at': proposal[4],
        'status': proposal[5],
        'votes': vote_summary
    }), 200


@app.route('/get-proposals', methods=['GET'])
def get_proposals():
    try:
        conn = sqlite3.connect(DB)
        c = conn.cursor()

        
        c.execute("SELECT id, title, description, created_by, created_at, status FROM proposals WHERE status = 'open'")
        proposals = c.fetchall()

        proposals_list = []
        for proposal in proposals:
            proposals_list.append({
                "id": proposal[0],
                "title": proposal[1],
                "description": proposal[2],
                "created_by": proposal[3],
                "created_at": proposal[4],
                "status": proposal[5],
            })

        conn.close()

        if not proposals_list:
            return jsonify({"message": "No open proposals found"}), 200

        return jsonify(proposals_list), 200

    except Exception as e:
        print(f"Error occurred: {e}") 
        return jsonify({"message": "Internal server error"}), 500

@app.route('/dao/rewards', methods=['GET'])
def view_rewards():
    user_id = verify_token(request.headers.get('Authorization'))
    if not user_id:
        return jsonify({'message': 'Invalid token'}), 401
    conn = sqlite3.connect(DB)
    c = conn.cursor()
    c.execute("SELECT SUM(reward) FROM dao_rewards WHERE user_id = ?", (user_id,))
    rewards = c.fetchone()[0]
    conn.close()
    return jsonify({'rewards': rewards if rewards else 0}), 200

def distribute_rewards():
    conn = sqlite3.connect(DB)
    c = conn.cursor()
    c.execute("SELECT user_id, SUM(weight) FROM votes GROUP BY user_id")
    voters = c.fetchall()
    for user_id, total_weight in voters:
        reward = total_weight * 0.001
        c.execute("INSERT INTO dao_rewards (user_id, reward) VALUES (?, ?)", (user_id, reward))
    conn.commit()
    conn.close()


@socketio.on('send_message') 
def handle_send_message(data):
    sender_id = data.get("sender_id")
    receiver_id = data.get("receiver_id")
    message = data.get("message")

    if not all([sender_id, receiver_id, message]):
        emit('error', {'message': 'Missing fields'})  
        return

    recipient_public_key = fetch_public_key(receiver_id)
    if not recipient_public_key:
        emit('error', {'message': "Recipient's public key not found"})
        return


    encrypted_message = encrypt_message(recipient_public_key, message)


    conn = sqlite3.connect("messages.db")
    c = conn.cursor()
    c.execute(
        "INSERT INTO messages (sender_id, receiver_id, message, timestamp) VALUES (?, ?, ?, ?)",
        (sender_id, receiver_id, encrypted_message, int(time.time()))
    )
    conn.commit()
    conn.close()

    emit('new_message', {'sender_id': sender_id, 'message': message, 'timestamp': int(time.time())}, room=receiver_id) 


@socketio.on('get_messages') 
def handle_get_messages(data):
    user_id = data.get("user_id")
    contact_id = data.get("contact_id")
    private_key_pem = data.get("private_key")

    if not all([user_id, contact_id, private_key_pem]):
        emit('error', {'message': 'Missing fields'})
        return
    conn = sqlite3.connect("messages.db")
    c = conn.cursor()
    c.execute(
        "SELECT sender_id, message, timestamp FROM messages WHERE (sender_id = ? AND receiver_id = ?) OR (sender_id = ? AND receiver_id = ?)",
        (user_id, contact_id, contact_id, user_id)
    )
    messages = c.fetchall()
    conn.close()

    decrypted_messages = []
    for sender_id, encrypted_message, timestamp in messages:
        try:
            decrypted = decrypt_message(private_key_pem, encrypted_message)
        except Exception as e:
            decrypted = f"Decryption failed. {e}" 
        decrypted_messages.append({
            "sender_id": sender_id,
            "message": decrypted,
            "timestamp": timestamp
        })

    emit('messages_retrieved', {'messages': decrypted_messages}) 


@app.errorhandler(404)
def forbidden(e):
    return render_template("404.html"), 404

@app.errorhandler(500)
def err(e):
    return render_template("500.html"), 500

@app.errorhandler(Exception)
def handle_generic_error(e):
    error_code = getattr(e, 'code', 500)
    return render_template("500.html", error_code=error_code, error_message=str(e)), error_code

if __name__ == "__main__":
    initialize_all_tables()
    socketio.run(app ,debug=True)
# a base for a defi