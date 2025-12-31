import requests
import json
import os
import time
from flask import Flask, request, jsonify, send_from_directory
from flask_cors import CORS
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad, pad
from base64 import b64decode, b64encode
import base64

app = Flask(__name__)
CORS(app, resources={r"/*": {"origins": "*"}})

# Add this for Vercel
# Vercel needs the app instance named 'app'
# and doesn't use the __main__ block for execution
# server.py is our entry point

# API Security Configuration
# These are the keys used to encrypt/decrypt communication between Frontend and Backend
API_SEC_KEY = b"SparkDevSecKey12" # 16 bytes
API_SEC_IV = b"SparkDevSecIV123" # 16 bytes

# Utkarsh specific keys
API_URL = "https://application.utkarshapp.com/index.php/data_model"
COMMON_KEY = b"%!^F&^$)&^$&*$^&"
COMMON_IV = b"#*v$JvywJvyJDyvJ"
key_chars = "%!F*&^$)_*%3f&B+"
iv_chars = "#*$DJvyw2w%!_-$@"

HEADERS = {
    "Authorization": "Bearer 152#svf346t45ybrer34yredk76t",
    "Content-Type": "text/plain; charset=UTF-8",
    "devicetype": "1",
    "host": "application.utkarshapp.com",
    "lang": "1",
    "user-agent": "okhttp/4.9.0",
    "userid": "0",
    "version": "152"
}

session = requests.Session()
user_auth = {"token": None, "jwt": None, "userid": "0", "key": None, "iv": None, "logged_in": False, "csrf": None, "last_login": 0}

REQUESTED_BATCHES_FILE = "requested_batches.json"
FAVORITES_FILE = "favorites.json"

def load_json(filename):
    if os.path.exists(filename):
        try:
            with open(filename, 'r') as f:
                data = json.load(f)
                return data if isinstance(data, list) else []
        except: return []
    return []

def save_json(filename, data):
    try:
        with open(filename, 'w') as f:
            json.dump(data, f)
    except: pass

# --- Communication Encryption ---
def encrypt_api_response(data):
    cipher = AES.new(API_SEC_KEY, AES.MODE_CBC, API_SEC_IV)
    raw = json.dumps(data).encode('utf-8')
    padded = pad(raw, AES.block_size)
    encrypted = cipher.encrypt(padded)
    return b64encode(encrypted).decode('utf-8')

def decrypt_api_request(enc_data):
    try:
        enc_bytes = b64decode(enc_data)
        cipher = AES.new(API_SEC_KEY, AES.MODE_CBC, API_SEC_IV)
        decrypted = unpad(cipher.decrypt(enc_bytes), AES.block_size)
        return json.loads(decrypted.decode('utf-8'))
    except: return None

# --- Utkarsh Logic ---
def decrypt_stream(enc):
    try:
        if not enc: return None
        enc_bytes = b64decode(enc)
        k = '%!$!%_$&!%F)&^!^'.encode('utf-8')
        i = '#*y*#2yJ*#$wJv*v'.encode('utf-8')
        cipher = AES.new(k, AES.MODE_CBC, i)
        decrypted_bytes = cipher.decrypt(enc_bytes)
        try: plaintext = unpad(decrypted_bytes, AES.block_size).decode('utf-8')
        except: plaintext = decrypted_bytes.decode('utf-8', errors='ignore')
        cleaned_json = ''
        for idx in range(len(plaintext)):
            try:
                json.loads(plaintext[:idx+1])
                cleaned_json = plaintext[:idx+1]  
            except json.JSONDecodeError: continue
        final_brace_index = cleaned_json.rfind('}')
        if final_brace_index != -1: cleaned_json = cleaned_json[:final_brace_index + 1]
        return cleaned_json
    except: return None

def encrypt_stream(plain_text):
    try:
        k = '%!$!%_$&!%F)&^!^'.encode('utf-8')
        i = '#*y*#2yJ*#$wJv*v'.encode('utf-8')
        cipher = AES.new(k, AES.MODE_CBC, i)
        padded_text = pad(plain_text.encode('utf-8'), AES.block_size)
        encrypted = cipher.encrypt(padded_text)
        return b64encode(encrypted).decode('utf-8')
    except: return None

def encrypt(data, use_common_key, key, iv):
    cipher_key, cipher_iv = (COMMON_KEY, COMMON_IV) if use_common_key else (key, iv)
    cipher = AES.new(cipher_key, AES.MODE_CBC, cipher_iv)
    padded_data = pad(json.dumps(data, separators=(",", ":")).encode(), AES.block_size)
    encrypted = cipher.encrypt(padded_data)
    return b64encode(encrypted).decode() + ":"

def decrypt(data, use_common_key, key, iv):
    cipher_key, cipher_iv = (COMMON_KEY, COMMON_IV) if use_common_key else (key, iv)
    try:
        if not data: return None
        encrypted_data = b64decode(data.split(":")[0])
        cipher = AES.new(cipher_key, AES.MODE_CBC, cipher_iv)
        decrypted_bytes = cipher.decrypt(encrypted_data)
        return unpad(decrypted_bytes, AES.block_size).decode()
    except: return None

def post_request_api(path, data=None, use_common_key=False, key=None, iv=None):
    try:
        current_headers = HEADERS.copy()
        if user_auth["jwt"]: current_headers["jwt"] = user_auth["jwt"]
        if user_auth["userid"]: current_headers["userid"] = user_auth["userid"]
        target_key = key if key else user_auth["key"]
        target_iv = iv if iv else user_auth["iv"]
        if not target_key or not target_iv: target_key, target_iv = COMMON_KEY, COMMON_IV
        encrypted_data = encrypt(data, use_common_key, target_key, target_iv) if data else data
        response = session.post(f"{API_URL}{path}", headers=current_headers, data=encrypted_data, timeout=30)
        decrypted_data = decrypt(response.text, use_common_key, target_key, target_iv)
        if decrypted_data: return json.loads(decrypted_data)
    except Exception as e: print(f"API Error at {path}: {e}")
    return {"status": False, "error": "Request failed"}

@app.route('/login', methods=['POST'])
def login():
    global user_auth
    mobile, password = os.environ.get("UTKARSH_EMAIL"), os.environ.get("UTKARSH_PASSWORD")
    if not mobile or not password: return jsonify({"status": False, "error": "Missing credentials"})
    try:
        r1 = session.get(base_url)
        csrf_token = r1.cookies.get('csrf_name')
        user_auth["csrf"] = csrf_token
        d1 = {'csrf_name': csrf_token, 'mobile': mobile, 'url': '0', 'password': password, 'submit': 'LogIn', 'device_token': 'null'}
        h = {'Host': 'online.utkarsh.com', 'Sec-Ch-Ua': '"Chromium";v="119", "Not?A_Brand";v="24"', 'Accept': 'application/json, text/javascript, */*; q=0.01', 'Content-Type': 'application/x-www-form-urlencoded; charset=UTF-8', 'X-Requested-With': 'XMLHttpRequest', 'Sec-Ch-Ua-Mobile': '?0', 'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.6045.199 Safari/537.36'}
        resp = session.post(login_url, data=d1, headers=h)
        data = resp.json()
        dec_resp = decrypt_stream(data.get("response"))
        if not dec_resp: return jsonify({"status": False, "error": "Login decryption failed"})
        dr1 = json.loads(dec_resp)
        if dr1.get("status"):
            user_auth["jwt"] = dr1.get("data", {}).get("jwt")
            user_auth["token"] = dr1.get("token")
            HEADERS["jwt"] = user_auth["jwt"]
            user_auth["key"] = "".join(key_chars[int(i)] for i in ("0" + "1524567456436545")[:16]).encode()
            user_auth["iv"] = "".join(iv_chars[int(i)] for i in ("0" + "1524567456436545")[:16]).encode()
            profile = post_request_api("/users/get_my_profile", use_common_key=True)
            if profile and profile.get("status"):
                uid = str(profile["data"]["id"])
                user_auth["userid"] = uid
                HEADERS["userid"] = uid
                user_auth["key"] = "".join(key_chars[int(i)] for i in (uid + "1524567456436545")[:16]).encode()
                user_auth["iv"] = "".join(iv_chars[int(i)] for i in (uid + "1524567456436545")[:16]).encode()
                user_auth["logged_in"] = True
                user_auth["last_login"] = time.time()
                return jsonify({"status": True, "payload": encrypt_api_response({"status": True})})
            return jsonify({"status": False, "error": "Profile failed"})
        return jsonify({"status": False, "error": dr1.get("message")})
    except Exception as e: return jsonify({"status": False, "error": str(e)})

@app.route('/batches')
def get_batches():
    if not user_auth["logged_in"]: return jsonify({"status": False, "error": "Not logged in"})
    data = post_request_api("/course/get_my_courses", data={"type": "1"})
    batches = []
    if data and data.get("status"):
        for item in data.get("data", []):
            batches.append({"id": str(item.get("id")), "title": item.get("title") or item.get("course_name"), "image": "/static/images/thumbnail.png", "course_name": item.get("course_name"), "requested": False})
    requested = load_json(REQUESTED_BATCHES_FILE)
    favorites = load_json(FAVORITES_FILE)
    for req in requested:
        req_id = req['id'] if isinstance(req, dict) else str(req)
        req_title = req.get('title', f"Batch {req_id}") if isinstance(req, dict) else f"Batch {req}"
        if not any(b['id'] == req_id for b in batches):
            batches.append({"id": req_id, "title": req_title, "image": "/static/images/thumbnail.png", "course_name": "Requested Batch", "requested": True})
    for b in batches: b['favorite'] = str(b['id']) in [str(f) for f in favorites]
    return jsonify({"status": True, "payload": encrypt_api_response(batches[::-1])})

@app.route('/request_batch', methods=['POST'])
def request_batch():
    dec_data = decrypt_api_request(request.json.get('payload'))
    bid = str(dec_data.get('batch_id')) if dec_data else None
    if not bid: return jsonify({"status": False, "error": "Batch ID required"})
    reqs = load_json(REQUESTED_BATCHES_FILE)
    exists = False
    for r in reqs:
        r_id = r['id'] if isinstance(r, dict) else str(r)
        if r_id == bid: exists = True; break
    if not exists:
        reqs.append({"id": bid, "title": f"Extracting {bid}..."})
        save_json(REQUESTED_BATCHES_FILE, reqs)
    return jsonify({"status": True, "payload": encrypt_api_response({"status": True})})

@app.route('/toggle_favorite', methods=['POST'])
def toggle_favorite():
    dec_data = decrypt_api_request(request.json.get('payload'))
    bid = str(dec_data.get('batch_id')) if dec_data else None
    favs = [str(f) for f in load_json(FAVORITES_FILE)]
    if bid in favs: favs.remove(bid)
    else: favs.append(bid)
    save_json(FAVORITES_FILE, favs)
    return jsonify({"status": True, "payload": encrypt_api_response({"status": True})})

@app.route('/batch/<batch_id>/content')
def get_batch_content(batch_id):
    if not user_auth["logged_in"]: return jsonify({"status": False, "error": "Not logged in"})
    videos, pdfs, dpps = [], [], []
    h = {'Host': 'online.utkarsh.com', 'token': user_auth['token'], 'jwt': user_auth['jwt']}
    reqs = load_json(REQUESTED_BATCHES_FILE)
    batch_name = None
    def process_layer_three(subject_id, topic_id):
        d9 = {"course_id": batch_id, "parent_id": batch_id, "layer": 3, "page": 1, "revert_api": "1#0#0#1", "subject_id": subject_id, "tile_id": 0, "topic_id": topic_id, "type": "content"}
        de4 = base64.b64encode(json.dumps(d9).encode()).decode()
        resp = session.post(layer_two_data_url, headers=h, data={'layer_two_input_data': de4, 'csrf_name': user_auth['csrf']})
        if resp.status_code != 200: return
        try:
            u7 = resp.json(); dec_u7 = decrypt_stream(u7.get("response"))
            if not dec_u7: return
            dr6 = json.loads(dec_u7)
            if dr6.get("status") and "data" in dr6 and "list" in dr6["data"]:
                for item in dr6["data"]["list"]:
                    ji, jt = item.get("id"), item.get("title")
                    payload = item.get("payload")
                    if not payload: continue
                    j4 = {"course_id": batch_id, "device_id": "server", "device_name": "server", "download_click": "0", "name": f"{ji}_0_0", "tile_id": payload.get("tile_id"), "type": "video"}
                    j5 = post_request_api(meta_source_url, j4, key=user_auth['key'], iv=user_auth['iv'])
                    cj = j5.get("data", {})
                    if not cj: continue
                    url = next((b.get("url") for b in reversed(cj.get("bitrate_urls", [])) if b.get("url")), cj.get("link", ""))
                    if url:
                        final_url = url.split("?Expires=")[0]
                        obj = {"id": ji, "title": jt, "url": final_url}
                        if ".pdf" in final_url.lower():
                            if "DPP" in jt.upper(): dpps.append(obj)
                            else: pdfs.append(obj)
                        else: videos.append(obj)
        except: pass
    try:
        d3 = {"course_id": batch_id, "revert_api": "1#0#0#1", "parent_id": 0, "tile_id": "15330", "layer": 1, "type": "course_combo"}
        de1 = encrypt_stream(json.dumps(d3))
        resp4 = session.post(tiles_data_url, headers=h, data={'tile_input': de1, 'csrf_name': user_auth['csrf']})
        if resp4.status_code == 200:
            dec_u4 = decrypt_stream(resp4.json().get("response"))
            if dec_u4:
                dr3 = json.loads(dec_u4)
                sub_courses = dr3.get("data", []) if isinstance(dr3.get("data"), list) else [dr3.get("data")]
                for layer1_item in sub_courses:
                    if not layer1_item: continue
                    if not batch_name: batch_name = layer1_item.get("title") or layer1_item.get("course_name")
                    fi = layer1_item.get("id") or batch_id
                    d5 = {"course_id": fi, "layer": 1, "page": 1, "parent_id": fi, "revert_api": "1#1#0#1", "tile_id": "0", "type": "content"}
                    de2 = encrypt_stream(json.dumps(d5))
                    resp5 = session.post(tiles_data_url, headers=h, data={'tile_input': de2, 'csrf_name': user_auth['csrf']})
                    if resp5.status_code != 200: continue
                    dec_u5 = decrypt_stream(resp5.json().get("response"))
                    if not dec_u5: continue
                    for subject in json.loads(dec_u5).get("data", {}).get("list", []):
                        sfi = subject.get("id")
                        d7 = {"course_id": fi, "parent_id": fi, "layer": 2, "page": 1, "revert_api": "1#0#0#1", "subject_id": sfi, "tile_id": 0, "topic_id": sfi, "type": "content"}
                        de3 = base64.b64encode(json.dumps(d7).encode()).decode()
                        resp6 = session.post(layer_two_data_url, headers=h, data={'layer_two_input_data': de3, 'csrf_name': user_auth['csrf']})
                        if resp6.status_code != 200: continue
                        dec_u6 = decrypt_stream(resp6.json().get("response"))
                        if not dec_u6: continue
                        for topic in json.loads(dec_u6).get("data", {}).get("list", []): process_layer_three(sfi, topic.get("id"))
    except: pass
    if batch_name:
        updated = False
        new_reqs = []
        for r in reqs:
            if isinstance(r, dict):
                if r['id'] == batch_id and r['title'] != batch_name: r['title'] = batch_name; updated = True
                new_reqs.append(r)
            else:
                if str(r) == batch_id: new_reqs.append({"id": batch_id, "title": batch_name}); updated = True
                else: new_reqs.append({"id": str(r), "title": f"Batch {r}"})
        if updated: save_json(REQUESTED_BATCHES_FILE, new_reqs)
    videos.sort(key=lambda x: str(x.get("id", "")), reverse=True)
    return jsonify({"status": True, "payload": encrypt_api_response({"videos": videos, "pdfs": pdfs, "dpps": dpps})})

@app.route('/')
def index():
    return jsonify({"status": True, "message": "API is working perfectly!"})
@app.route('/<path:path>')
def static_files(path): return send_from_directory('static', path)

if __name__ == '__main__':
    port = int(os.environ.get("PORT", 5000))
    app.run(host='0.0.0.0', port=port)
