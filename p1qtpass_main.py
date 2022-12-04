import base64
import os
import sqlite3
from uuid import uuid4
from Crypto import Random as CryptoRandom
from Crypto.Cipher import AES
from Crypto.Hash import SHA256

dir_ = os.path.expanduser('~') + 'p1qtpass'
config_path_default = dir_ + '.config'
pass_path_default = dir_ + '.passwords.db'

runtime_ctx = {
    # Словарь с данными для дешифровки/шифровки паролей, а также текущей базой данных и файлом конфигурации.
    'encryptor': None,
    'db': None,
    'config': None,
}


def get_random_salt():
    # Функция, генерирующая соль/надежный пароль.
    return str(uuid4())


class Encryptor:
    # Класс, с помощью которого осуществляется взаимодействие с паролями базы данных.
    def __init__(self, master_key):
        self.key = master_key

    def get_sha_key(self):
        # Функция шифрования пароля алгоритмом SHA256.
        return SHA256.new(self.key).digest()

    def encrypt(self, plaintext):
        # Функция шифрования пароля алгоритмом AES.
        iv = CryptoRandom.new().read(AES.block_size)
        aes = AES.new(self.get_sha_key(), AES.MODE_CBC, iv)
        padding = AES.block_size - len(plaintext) % AES.block_size
        plaintext += bytes([padding]) * padding
        ciphertext = iv + aes.encrypt(plaintext)
        return base64.b64encode(ciphertext)

    def decrypt(self, ciphertext):
        # Функция дешифрования пароля алгоритмом AES.
        ciphertext = base64.b64decode(ciphertext)
        iv = ciphertext[:AES.block_size]
        ciphertext = ciphertext[AES.block_size:]
        aes = AES.new(self.get_sha_key(), AES.MODE_CBC, iv)
        plaintext = aes.decrypt(ciphertext)
        padding = plaintext[-1]
        if plaintext[-padding:] != bytes([padding]) * padding:
            raise ValueError("Invalid padding")
        return plaintext[:-padding]


class Config:
    # Класс, сделанный для создания файла конфигурации.
    def __init__(self):
        self.salt = get_random_salt()


def add_password(name, url, login, password, notes=''):
    # Функцияя добавления пароля в базу данных.
    con = sqlite3.connect("passwords.db")
    cur = con.cursor()
    salt = ''  # get_random_salt()
    uid = str(uuid4())
    cur.execute("""INSERT INTO passwords(name, url, login, password, notes, uid, salt)
                    VALUES(?, ?, ?, ?, ?, ?, ?) 
                """, (name, url, login, runtime_ctx['encryptor'].encrypt(password.encode()), notes, uid, salt,))
    con.commit()


def edit_password(name, url, login, password, notes, uid):
    # Функция редактирования пароля.
    con = sqlite3.connect("passwords.db")
    cur = con.cursor()
    cur.execute("""UPDATE passwords
                   SET name = ?,
                       url = ?,
                       login = ?,
                       password = ?,
                       notes = ?
                    WHERE uid=?
                    """, (name, url, login, runtime_ctx['encryptor'].encrypt(password.encode()),
                          notes, uid,))
    con.commit()


def get_password(name):
    # Функция получения пароля из базы данных.
    con = sqlite3.connect("passwords.db")
    cur = con.cursor()
    password = cur.execute("""SELECT password FROM passwords
                    WHERE name = ?
                """, (name,)).fetchone()[0]
    password = runtime_ctx['encryptor'].decrypt(password)
    con.close()
    return password.decode()


def get_all_passwords():
    # Функция, записывающая все пароли пользователя в массив для дальнейшей перезаписи.
    con = sqlite3.connect("passwords.db")
    cur = con.cursor()
    passwords = cur.execute("""SELECT password, uid from passwords""").fetchall()
    decrypted_passwords = []
    for password, uid in passwords:
        decrypted_passwords.append((runtime_ctx['encryptor'].decrypt(password).decode('utf-8'), uid))
    return decrypted_passwords


def refresh_all_passwords(decrypted_passwords):
    # Функция, обновляющая все пароли пользователя при смена мастер-ключа.
    con = sqlite3.connect("passwords.db")
    cur = con.cursor()
    for password, uid in decrypted_passwords:
        new_secret = runtime_ctx['encryptor'].encrypt(password.encode())
        cur.execute("""UPDATE passwords
                           SET password = ?
                            WHERE uid=?
                            """, (new_secret, uid,))
        con.commit()
    con.close()
    runtime_ctx['config'] = Config()
    create_config()
    create_validation_key()


def init_tables():
    # Функция, создающяя базу данных при ее отсутствии.
    con = sqlite3.connect("passwords.db")
    cur = con.cursor()
    cur.execute("""CREATE TABLE IF NOT EXISTS users(
                   userid INTEGER PRIMARY KEY,
                   key STRING,
                   value STRING);
                """)
    cur.execute("""CREATE TABLE IF NOT EXISTS passwords(
                   id INTEGER PRIMARY KEY,
                   name STRING,
                   url STRING,
                   login STRING,
                   password STRING,
                   notes BLOB,
                   uid STRING UNIQUE,
                   salt STRING);
                """)
    con.commit()


def add_user(key, value):
    # Функция добавления пользователя в базу данных.
    con = sqlite3.connect("passwords.db")
    cur = con.cursor()
    cur.execute("""DELETE FROM users""")
    cur.execute("""INSERT INTO users (key, value) 
                VALUES (?, ?) """, (key, value,))
    con.commit()


def get_user(key):
    # Функция получения данных о пользователе из базы данных.
    con = sqlite3.connect("passwords.db")
    cur = con.cursor()
    cur.execute("""SELECT value FROM users WHERE key = ?""",
                (key,))
    return cur.fetchone()[0]


def create_validation_key():
    # Функция, шифрующая мастер-ключ и добавляющая его в таблицу users базы данных.
    salted_key = runtime_ctx['encryptor'].key + runtime_ctx['config'].salt.encode()
    add_user("validation_key", runtime_ctx['encryptor'].encrypt(salted_key))


def create_database(master):
    # Функция вызывающая создание базы данных, данных о мастер-ключе и добавление его в базу данных.
    runtime_ctx['encryptor'] = Encryptor(master.encode())
    init_tables()
    create_validation_key()
    return True


def create_config():
    # Функция создания файла конфигурации.
    cfg = open('config.txt', 'w')
    cfg.write(runtime_ctx['config'].salt)
    cfg.close()
    return True


def check_valid_master_key(master_key):
    # Функция, проверяющая введенный мастер-ключ на правильность.
    runtime_ctx['encryptor'] = Encryptor(master_key.encode())
    validation_key_encrypted = get_user("validation_key")
    cfg = open('config.txt', 'r')
    salt = cfg.readline()
    cfg.close()
    salted_key = runtime_ctx['encryptor'].key + salt.encode()
    try:
        if salted_key == runtime_ctx['encryptor'].decrypt(validation_key_encrypted):
            return True
    except ValueError:
        return False
    return False


def launch_p1qtpass(master):
    # Основная функция, которая при первом запуске программы вызывает создание базы даннх, файла конфигурации.
    if not os.path.isfile("passwords.db") or not os.path.isfile("config"):
        runtime_ctx['config'] = Config()
    if not os.path.isfile("passwords.db"):
        res = create_database(master)
        if res is False:
            return False
    if not os.path.isfile("config.txt"):
        res1 = create_config()
        if res1 is False:
            return False
    return True
