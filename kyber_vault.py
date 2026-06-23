import os, sys, json, struct, hashlib, hmac, secrets, string, getpass
from typing import Optional
from mlkem_core import keygen, kyber_encrypt, kyber_decrypt, H, _PB12, K, PK_LEN

VAULT_VERSION = 2
VAULT_MAGIC   = b"KYBERVLT2"  # 9 байт

# ─── Вспомогательные примитивы ───────────────────────────────────

def _pbkdf2(password: bytes, salt: bytes) -> bytes:
    return hashlib.pbkdf2_hmac('sha256', password, salt, 600_000, 32)

def _hmac_sha256(key: bytes, data: bytes) -> bytes:
    return hmac.new(key, data, hashlib.sha256).digest()

def _xor_stream_encrypt(key: bytes, data: bytes) -> bytes:
    """XOR с SHA-256 keystream — для защиты SK мастер-ключом."""
    ks = b""
    i  = 0
    while len(ks) < len(data):
        ks += hashlib.sha256(key + i.to_bytes(4, 'big')).digest()
        i  += 1
    ct  = bytes(a ^ b for a, b in zip(data, ks))
    mac = _hmac_sha256(key, ct)
    return mac + ct  # 32 байта MAC + шифртекст

def _xor_stream_decrypt(key: bytes, enc: bytes) -> bytes:
    mac, ct = enc[:32], enc[32:]
    if not hmac.compare_digest(mac, _hmac_sha256(key, ct)):
        raise ValueError("Неверный мастер-пароль")
    ks = b""
    i  = 0
    while len(ks) < len(ct):
        ks += hashlib.sha256(key + i.to_bytes(4, 'big')).digest()
        i  += 1
    return bytes(a ^ b for a, b in zip(ct, ks))

# ─── Генератор паролей ───────────────────────────────────────────

def generate_password(length=20, upper=True, digits=True, symbols=True) -> str:
    alpha = string.ascii_lowercase
    if upper:   alpha += string.ascii_uppercase
    if digits:  alpha += string.digits
    if symbols: alpha += "!@#$%^&*()-_=+[]{}|;:,.<>?"
    while True:
        pwd = ''.join(secrets.choice(alpha) for _ in range(length))
        if upper   and not any(c in string.ascii_uppercase for c in pwd): continue
        if digits  and not any(c in string.digits for c in pwd):           continue
        if symbols and not any(c in "!@#$%^&*()-_=+[]{}|;:,.<>?" for c in pwd): continue
        return pwd

# ═════════════════════════════════════════════════════════════════
#  KyberVault
# ═════════════════════════════════════════════════════════════════

class KyberVault:
    def __init__(self):
        self._entries:  dict          = {}
        self._pk:       Optional[bytes] = None
        self._sk:       Optional[bytes] = None
        self._kdf_salt: Optional[bytes] = None

    def create(self, master_password: str):
        print("\n[*] Генерация ML-KEM (Kyber-512) ключевой пары...")
        self._pk, self._sk = keygen()
        self._kdf_salt     = os.urandom(32)
        self._entries      = {}
        print(f"[✓] PK={len(self._pk)}B  SK={len(self._sk)}B")

    def save(self, path: str, master_password: str):
        if not self._pk:
            raise RuntimeError("Хранилище не открыто")

        # 1. Мастер-ключ из пароля
        master_key = _pbkdf2(master_password.encode(), self._kdf_salt)

        # 2. Защищаем SK мастер-ключом (XOR-stream)
        sk_enc = _xor_stream_encrypt(master_key, self._sk)

        # 3. Шифруем данные через Kyber-CPA (Module-LWE — диофантовы уравнения)
        vault_json = json.dumps(self._entries, ensure_ascii=False).encode('utf-8')
        data_ct    = kyber_encrypt(self._pk, vault_json)

        def pack(b): return struct.pack(">I", len(b)) + b

        body = (
            VAULT_MAGIC +
            struct.pack(">H", VAULT_VERSION) +
            self._kdf_salt +
            self._pk +
            pack(sk_enc) +
            pack(data_ct)
        )

        # HMAC целостности
        mac = _hmac_sha256(master_key, body)

        with open(path, 'wb') as f:
            f.write(body + mac)

        print(f"[✓] Сохранено: {path} ({len(body)+32} байт | Kyber-CPA шифрование)")

    def load(self, path: str, master_password: str):
        with open(path, 'rb') as f:
            raw = f.read()

        if not raw.startswith(VAULT_MAGIC):
            raise ValueError("Неверный формат файла")

        pos = len(VAULT_MAGIC)
        version = struct.unpack(">H", raw[pos:pos+2])[0]; pos += 2
        if version != VAULT_VERSION:
            raise ValueError(f"Неподдерживаемая версия: {version}")

        kdf_salt = raw[pos:pos+32]; pos += 32
        pk       = raw[pos:pos+PK_LEN]; pos += PK_LEN

        def read_blob(p):
            l = struct.unpack(">I", raw[p:p+4])[0]
            return raw[p+4:p+4+l], p+4+l

        sk_enc,  pos = read_blob(pos)
        data_ct, pos = read_blob(pos)
        stored_mac   = raw[pos:pos+32]

        # 1. PBKDF2
        print("[*] Деривация ключа (PBKDF2-SHA256, 600k итераций)...")
        master_key = _pbkdf2(master_password.encode(), kdf_salt)

        # 2. Проверка HMAC
        body = raw[:-32]
        if not hmac.compare_digest(stored_mac, _hmac_sha256(master_key, body)):
            raise ValueError("Неверный мастер-пароль")

        # 3. Восстанавливаем SK
        sk = _xor_stream_decrypt(master_key, sk_enc)

        # 4. Расшифровываем данные через Kyber-CPA (диофантовы уравнения)
        try:
            vault_bytes = kyber_decrypt(sk, data_ct)
            self._entries = json.loads(vault_bytes.decode('utf-8'))
        except Exception as e:
            raise ValueError(f"Ошибка расшифровки данных: {e}")

        self._pk       = pk
        self._sk       = sk
        self._kdf_salt = kdf_salt
        print(f"[✓] Открыто через Kyber-CPA. Записей: {len(self._entries)}")

    # ── CRUD ─────────────────────────────────────────────────────

    def add_entry(self, service, login, password, notes=""):
        self._entries[service] = {"login": login, "password": password, "notes": notes}

    def get_entry(self, service) -> Optional[dict]:
        return self._entries.get(service)

    def list_services(self) -> list:
        return sorted(self._entries.keys())

    def delete_entry(self, service) -> bool:
        return bool(self._entries.pop(service, None))

    def update_password(self, service, new_password) -> bool:
        if service in self._entries:
            self._entries[service]["password"] = new_password
            return True
        return False


# ─── CLI ─────────────────────────────────────────────────────────

VAULT_FILE = "vault.kybr"

def run_cli():
    print("""
╔══════════════════════════════════════════════════════════╗
║   🔐 KYBER VAULT v2 — Диофантовые уравнения             ║
║       Kyber-CPA (Module-LWE) · FIPS 203                 ║
╚══════════════════════════════════════════════════════════╝""")
    vault = KyberVault()
    if os.path.exists(VAULT_FILE):
        master = getpass.getpass("Мастер-пароль: ")
        try:
            vault.load(VAULT_FILE, master)
        except ValueError as e:
            print(f"[✗] {e}"); sys.exit(1)
    else:
        while True:
            master = getpass.getpass("Мастер-пароль (мин. 8): ")
            if len(master) < 8: continue
            if master != getpass.getpass("Подтвердите: "): continue
            break
        vault.create(master)
        vault.save(VAULT_FILE, master)

    while True:
        print("\n1.Добавить  2.Найти  3.Список  4.Удалить  5.Генератор  0.Выйти")
        choice = input("→ ").strip()
        if choice == "1":
            svc = input("Сервис: ").strip()
            lgn = input("Логин: ").strip()
            if input("Генерировать пароль? [y/n]: ").lower() == 'y':
                pwd = generate_password(int(input("Длина [20]: ").strip() or "20"))
                print(f"  → {pwd}")
            else:
                pwd = getpass.getpass("Пароль: ")
            vault.add_entry(svc, lgn, pwd, input("Заметки: ").strip())
            vault.save(VAULT_FILE, master)
        elif choice == "2":
            e = vault.get_entry(input("Сервис: ").strip())
            print(f"  {e}" if e else "  Не найден")
        elif choice == "3":
            [print(f"  • {s}") for s in vault.list_services()]
        elif choice == "4":
            svc = input("Сервис: ").strip()
            vault.delete_entry(svc); vault.save(VAULT_FILE, master)
        elif choice == "5":
            print(f"  → {generate_password(int(input('Длина [20]: ').strip() or '20'))}")
        elif choice == "0":
            vault.save(VAULT_FILE, master); break

if __name__ == "__main__":
    run_cli()


# ─── Безопасное удаление файла хранилища ─────────────────────────

def secure_delete(path: str, passes: int = 3) -> bool:
    """
    Безопасное удаление файла:
    1. Перезапись случайными байтами (passes раз)
    2. Перезапись нулями
    3. Удаление файла
    Предотвращает восстановление данных утилитами forensic-анализа.
    """
    if not os.path.exists(path):
        return False
    size = os.path.getsize(path)
    try:
        with open(path, 'r+b') as f:
            for _ in range(passes):
                f.seek(0)
                f.write(os.urandom(size))
                f.flush()
                os.fsync(f.fileno())
            # Финальная перезапись нулями
            f.seek(0)
            f.write(b'\x00' * size)
            f.flush()
            os.fsync(f.fileno())
        os.remove(path)
        return True
    except Exception:
        # Если безопасное удаление не удалось — обычное
        try:
            os.remove(path)
            return True
        except Exception:
            return False
