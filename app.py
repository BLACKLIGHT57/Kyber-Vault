"""
Kyber Vault v2 — Flask бэкенд
Запуск: python app.py  → открыть http://localhost:5000
"""
import os, json, base64
from flask import Flask, request, jsonify, session, send_from_directory
from kyber_vault import KyberVault, generate_password

app = Flask(__name__, static_folder='static')
app.secret_key = os.urandom(32)

_vaults  = {}
_masters = {}

VAULT_DIR = os.path.join(os.path.dirname(__file__), 'vaults')
os.makedirs(VAULT_DIR, exist_ok=True)

def vault_path(name): return os.path.join(VAULT_DIR, f'{name}.kybr')
def get_vault():      return _vaults.get(session.get('sid'))
def get_master():     return _masters.get(session.get('sid'))

# ── Безопасное удаление файла ────────────────────────────────────
def secure_delete(path: str, passes: int = 3) -> bool:
    """Перезаписывает файл случайными байтами перед удалением."""
    try:
        size = os.path.getsize(path)
        with open(path, 'r+b') as f:
            for _ in range(passes):
                f.seek(0)
                f.write(os.urandom(size))
                f.flush()
                os.fsync(f.fileno())
        os.remove(path)
        return True
    except Exception:
        return False

# ── Маршруты ─────────────────────────────────────────────────────

@app.route('/')
def index():
    return send_from_directory('static', 'index.html')

@app.route('/api/vaults')
def list_vaults():
    vs = []
    for f in os.listdir(VAULT_DIR):
        if f.endswith('.kybr'):
            path = os.path.join(VAULT_DIR, f)
            vs.append({'name': f[:-5], 'size': os.path.getsize(path)})
    return jsonify(vs)

@app.route('/api/create', methods=['POST'])
def create():
    d    = request.json
    name = d.get('name', '').strip()
    pwd  = d.get('password', '')
    if not name:     return jsonify(error='Укажите имя'), 400
    if len(pwd) < 8: return jsonify(error='Минимум 8 символов'), 400
    if os.path.exists(vault_path(name)):
        return jsonify(error='Хранилище уже существует'), 400
    v = KyberVault()
    v.create(pwd)
    v.save(vault_path(name), pwd)
    sid = base64.b64encode(os.urandom(16)).decode()
    session['sid'] = sid; session['vname'] = name
    _vaults[sid]   = v;   _masters[sid]   = pwd
    return jsonify(ok=True, name=name)

@app.route('/api/open', methods=['POST'])
def open_vault():
    d    = request.json
    name = d.get('name', '')
    pwd  = d.get('password', '')
    if not os.path.exists(vault_path(name)):
        return jsonify(error='Хранилище не найдено'), 404
    v = KyberVault()
    try:
        v.load(vault_path(name), pwd)
    except ValueError as e:
        return jsonify(error=str(e)), 401
    sid = base64.b64encode(os.urandom(16)).decode()
    session['sid'] = sid; session['vname'] = name
    _vaults[sid]   = v;   _masters[sid]   = pwd
    size = os.path.getsize(vault_path(name))
    return jsonify(ok=True, name=name, size=size, count=len(v.list_services()))

@app.route('/api/entries')
def entries():
    v = get_vault()
    if not v: return jsonify(error='Не авторизован'), 401
    return jsonify([{'service': svc, **v.get_entry(svc)} for svc in v.list_services()])

@app.route('/api/entries', methods=['POST'])
def add_entry():
    v = get_vault(); m = get_master()
    if not v: return jsonify(error='Не авторизован'), 401
    d   = request.json
    svc = d.get('service', '').strip()
    if not svc: return jsonify(error='Укажите сервис'), 400
    v.add_entry(svc, d.get('login',''), d.get('password',''), d.get('notes',''))
    v.save(vault_path(session['vname']), m)
    return jsonify(ok=True)

@app.route('/api/entries/<service>', methods=['PUT'])
def update_entry(service):
    v = get_vault(); m = get_master()
    if not v: return jsonify(error='Не авторизован'), 401
    d = request.json
    v.add_entry(service, d.get('login',''), d.get('password',''), d.get('notes',''))
    v.save(vault_path(session['vname']), m)
    return jsonify(ok=True)

@app.route('/api/entries/<service>', methods=['DELETE'])
def delete_entry(service):
    v = get_vault(); m = get_master()
    if not v: return jsonify(error='Не авторизован'), 401
    v.delete_entry(service)
    v.save(vault_path(session['vname']), m)
    return jsonify(ok=True)

@app.route('/api/generate')
def gen_pwd():
    length  = int(request.args.get('length', 20))
    symbols = request.args.get('symbols', 'true') == 'true'
    upper   = request.args.get('upper',   'true') == 'true'
    digits  = request.args.get('digits',  'true') == 'true'
    return jsonify(password=generate_password(length, upper, digits, symbols))

@app.route('/api/info')
def info():
    v = get_vault()
    if not v: return jsonify(error='Не авторизован'), 401
    name = session.get('vname', '')
    size = os.path.getsize(vault_path(name)) if name else 0
    return jsonify(
        name     = name,
        count    = len(v.list_services()),
        size     = size,
        algo     = 'Kyber-CPA (Module-LWE)',
        standard = 'FIPS 203 / NIST 2024',
        pk_size  = len(v._pk) if v._pk else 0,
        sk_size  = len(v._sk) if v._sk else 0,
    )

# ── Безопасное удаление хранилища ────────────────────────────────
@app.route('/api/vaults/<name>', methods=['DELETE'])
def delete_vault(name):
    path = vault_path(name)
    if not os.path.exists(path):
        return jsonify(error='Хранилище не найдено'), 404

    # Если это текущее открытое хранилище — закрываем сессию
    if session.get('vname') == name:
        sid = session.get('sid')
        _vaults.pop(sid, None)
        _masters.pop(sid, None)
        session.clear()

    if secure_delete(path):
        return jsonify(ok=True, message=f'Хранилище «{name}» безопасно удалено (3 прохода перезаписи)')
    else:
        return jsonify(error='Ошибка при удалении файла'), 500

@app.route('/api/logout', methods=['POST'])
def logout():
    sid = session.get('sid')
    _vaults.pop(sid, None)
    _masters.pop(sid, None)
    session.clear()
    return jsonify(ok=True)

if __name__ == '__main__':
    print('\n🔐 Kyber Vault v2 → http://localhost:5000')
    print('   Шифрование: Kyber-CPA (Module-LWE / диофантовы уравнения)\n')
    app.run(debug=False, port=5000)
