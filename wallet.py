import os
import requests
import json
from ecdsa import SigningKey, SECP256k1
import hashlib
from mnemonic import Mnemonic
from getpass import getpass
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend
import base64
import time
os.system('clear')
SERVER = 'https://laptop-ubuntu.tail6eefa7.ts.net'

def banner():
    print("""⠀
    ⠀⠀⠀⠀⠀⠀⠀⣀⣤⣴⣶⣾⣿⣿⣿⣿⣷⣶⣦⣤⣀⠀⠀⠀⠀⠀⠀⠀⠀
    ⠀⠀⠀⠀⠀⣠⣴⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣦⣄⠀⠀⠀⠀⠀
    ⠀⠀⠀⣠⣾⣿⣿⣿⣿⣿⣿⣿⣿⣿⡿⠿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣷⣄⠀⠀⠀
    ⠀⠀⣴⣿⣿⣿⣿⣿⣿⣿⠟⠿⠿⡿⠀⢰⣿⠁⢈⣿⣿⣿⣿⣿⣿⣿⣿⣦⠀⠀
    ⠀⣼⣿⣿⣿⣿⣿⣿⣿⣿⣤⣄⠀⠀⠀⠈⠉⠀⠸⠿⣿⣿⣿⣿⣿⣿⣿⣿⣧⠀
    ⢰⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⡏⠀⠀⢠⣶⣶⣤⡀⠀⠈⢻⣿⣿⣿⣿⣿⣿⣿⡆
    ⣾⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⠃⠀⠀⠼⣿⣿⡿⠃⠀⠀⢸⣿⣿⣿⣿⣿⣿⣿⣷
    ⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⡟⠀⠀⢀⣀⣀⠀⠀⠀⠀⢴⣿⣿⣿⣿⣿⣿⣿⣿⣿
    ⢿⣿⣿⣿⣿⣿⣿⣿⢿⣿⠁⠀⠀⣼⣿⣿⣿⣦⠀⠀⠈⢻⣿⣿⣿⣿⣿⣿⣿⡿
    ⠸⣿⣿⣿⣿⣿⣿⣏⠀⠀⠀⠀⠀⠛⠛⠿⠟⠋⠀⠀⠀⣾⣿⣿⣿⣿⣿⣿⣿⠇
    ⠀⢻⣿⣿⣿⣿⣿⣿⣿⣿⠇⠀⣤⡄⠀⣀⣀⣀⣀⣠⣾⣿⣿⣿⣿⣿⣿⣿⡟⠀
    ⠀⠀⠻⣿⣿⣿⣿⣿⣿⣿⣄⣰⣿⠁⢀⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⠟⠀⠀
    ⠀⠀⠀⠙⢿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⡿⠋⠀⠀⠀
    ⠀⠀⠀⠀⠀⠙⠻⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⠟⠋⠀⠀⠀⠀⠀
    ⠀⠀⠀⠀⠀⠀⠀⠀⠉⠛⠻⠿⢿⣿⣿⣿⣿⡿⠿⠟⠛⠉⠀⠀⠀⠀⠀⠀⠀⠀""")
    
class Wallet:
    def __init__(self):
        self.private_key = None
        self.address = None
        self.username = ''

    def generate(self):
        mnemo = Mnemonic("english")
        phrase = mnemo.generate()
        os.system('clear')
        print(f"\nSAVE THIS SEED: {phrase}\n")
        seed = mnemo.to_seed(phrase)
        self.private_key = SigningKey.from_string(seed[:32], curve=SECP256k1)
        self.address = hashlib.sha256(
            self.private_key.verifying_key.to_string()
        ).hexdigest()
        self.username = input("write username: ")
        self._save_to_file(phrase, self.username)
        return self

    def _save_to_file(self, phrase, username):
        pin = getpass("Choose a 6-digit PIN: ")
        while len(pin) != 6 or not pin.isdigit():
            pin = getpass("PIN must be 6 digits: ")
        
        salt = os.urandom(16)
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
            backend=default_backend()
        )
        key = base64.urlsafe_b64encode(kdf.derive(pin.encode()))
        fernet = Fernet(key)
        
        key_data = {
            'phrase': phrase,
            'private_key': base64.b64encode(
                self.private_key.to_pem()
            ).decode(),
            'username': username
        }
        encrypted = fernet.encrypt(json.dumps(key_data).encode())
        
        with open(f"{self.username}.dat", 'wb') as f:
            f.write(base64.b64encode(salt) + b'\n')
            f.write(encrypted)
        os.system('clear')
        print(f"Wallet saved to {self.username}.dat")

    def load(self, path):
        pin = getpass("Enter PIN: ")
        with open(path, 'rb') as f:
            salt_line = f.readline().strip()
            encrypted = f.read()
        
        salt = base64.b64decode(salt_line)
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
            backend=default_backend()
        )
        key = base64.urlsafe_b64encode(kdf.derive(pin.encode()))
        fernet = Fernet(key)
        
        try:
            decrypted = fernet.decrypt(encrypted)
        except:
            os.system('clear')
            print("Decryption failed. Wrong PIN?")
            raise
        
        key_data = json.loads(decrypted)
        self.private_key = SigningKey.from_pem(
            base64.b64decode(key_data['private_key'])
        )
        self.address = hashlib.sha256(
            self.private_key.verifying_key.to_string()
        ).hexdigest()
        self.username = key_data.get('username', '')
        return self

    def load_from_private_key(self, pem):
        try:
            self.private_key = SigningKey.from_pem(pem)
            self.address = hashlib.sha256(
                self.private_key.verifying_key.to_string()
            ).hexdigest()
            self.username = 'Imported Wallet'
            return self
        except Exception as e:
            print(f"Invalid private key: {e}")
            raise

    def recover_from_seed(self, phrase):
        mnemo = Mnemonic("english")
        if not mnemo.check(phrase):
            raise ValueError("Invalid seed phrase")
        seed = mnemo.to_seed(phrase)
        self.private_key = SigningKey.from_string(seed[:32], curve=SECP256k1)
        self.address = hashlib.sha256(
            self.private_key.verifying_key.to_string()
        ).hexdigest()
        self.username = input("write a username: ")
        self._save_to_file(phrase, self.username)
        return self

    def send(self, recipient, amount, message=''):
        hashed_msg = hashlib.sha256(message.encode()).hexdigest()
        tx = {
            'sender': self.address,
            'recipient': recipient,
            'amount': amount,
            'message': hashed_msg
        }
        res = requests.post(f"{SERVER}/tx/new", json=tx)
        print("Transaction status:", res.text)

    def balance(self):
        res = requests.get(f"{SERVER}/balance/{self.address}")
        balance = res.json().get('balance', 0)
        print(f"\nWallet Balance: {balance:.5f} KNC")

    def get_transaction_history(self):
        os.system('clear')
        res = requests.get(f"{SERVER}/chain")
        if res.status_code != 200:
            print("Failed to fetch blockchain")
            return []
        chain = res.json().get('chain', [])
        history = []
        for block in chain:
            for tx in block.get('transactions', []):
                if tx.get('sender') == self.address or tx.get('recipient') == self.address:
                    history.append({
                        'block_index': block['index'],
                        'timestamp': block['timestamp'],
                        'transaction': tx
                    })
        return history

    def format_blockchain(self, chain):
        formatted = []
        for block in chain:
            block_hash = hashlib.sha256(
                json.dumps(block, sort_keys=True).encode()
            ).hexdigest()
            
            transactions = []
            for tx in block.get('transactions', []):
                sender = tx['sender'][:6] + '...' if tx['sender'] != '0' else '0...'
                recipient = tx['recipient'][:6] + '...'
                amount = f"{tx['amount']:.5f}"
                transactions.append(f"   {sender} → {recipient}: {amount}")
            
            formatted_block = (
                f"🔗 Block #{block['index']}\n"
                f"⏰ Time: {time.ctime(block['timestamp'])}\n"
                f"📝 Transactions ({len(transactions)}):\n" + '\n'.join(transactions) + "\n"
                f"🔨 Proof: {block['proof']}\n"
                f"🔗 Previous Hash: {block['previous_hash']}\n"
                f"🆔 Block Hash: {block_hash}\n"
            )
            formatted.append(formatted_block)
        return '\n'.join(formatted)

def menu():
    banner()
    wallet = Wallet()
    print("\n========== KendCoin Wallet ==========\n")
    print("1. Create Wallet\n2. Load Wallet\n3. Recover Wallet\n4. Login with Private Key\n5. Exit")
    choice = input("\nChoice: ")

    if choice == '1':
        wallet.generate()
        os.system('clear')
        banner()
        print(f"\nLogged in as: {wallet.username}")
        print(f"\nAddress: {wallet.address}")        
    elif choice == '2':
        os.system('clear')
        banner()
        print("\n========= KendCoin Wallet ========\n")
        print("Available Wallet in this Device\n")
        os.system('ls -1 *.dat')
        path = input("\n\nSELECT WALLET: ")
        wallet.load(path)
        os.system('clear')        
        
    elif choice == '3':
        banner()
        phrase = input("\nEnter seed phrase: ")
        wallet.recover_from_seed(phrase)
        print(f"\nLogged in as: {wallet.username}")
        print(f"\nAddress: {wallet.address}")
        os.system('clear')
    elif choice == '4':
        pem = getpass("\nPaste private key PEM (start with -----BEGIN EC PRIVATE KEY-----): ")
        wallet.load_from_private_key(pem)
        print(f"\nLogged in as imported wallet")
        print(f"\nAddress: {wallet.address}")
        os.system('clear')
    else:
        return

    while True:
        banner()
        print("\n========= KendCoin Wallet =========\n")
        print(f"\nLogged in as: {wallet.username}")
        print(f"\nWallet Address: {wallet.address}\n")
        wallet.balance()
        print(f"==================================")
        print("\n\n1. Send\n2. Balance\n3. Transaction History\n4. View Blockchain\n5. View Wallet Info\n6. Exit")
        cmd = input("\nCommand: ")
        if cmd == '1':
            recipient = input("\nRecipient address: ")
            amount = float(input("\nAmount: "))
            message = input("\nEnter to confirm..")
            wallet.send(recipient, amount, message)
        elif cmd == '2':
            wallet.balance()
        elif cmd == '3':
            history = wallet.get_transaction_history()
            os.system('clear')
            banner()
            print("\n--- Transaction History ---")
            for entry in history:
                tx = entry['transaction']
                print(f"\nBlock #{entry['block_index']} ({time.ctime(entry['timestamp'])})")
                print(f"From: {tx['sender']}")
                print(f"To: {tx['recipient']}")
                print(f"Amount: {tx['amount']:.5f}")
                print(f"Message Hash: {tx['message']}")
        elif cmd == '4':
            res = requests.get(f"{SERVER}/chain")
            if res.status_code == 200:
                chain = res.json().get('chain', [])
                os.system('clear')
                print(f"\nBlockchain length: {len(chain)}")
                print("\n" + wallet.format_blockchain(chain))
            else:
                print("\nFailed to fetch blockchain")
        elif cmd == '5':
            banner()
            print(f"###############################")
            print(f"\nUsername: {wallet.username}")
            print(f"\nAddress: {wallet.address}")
            print(f"\nPrivate Key:\n{wallet.private_key.to_pem().decode()}")
            print(f"###############################\n")

        elif cmd == '6':
            break

if __name__ == '__main__':
    menu()
