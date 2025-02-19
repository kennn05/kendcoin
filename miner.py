from flask import Flask, request, jsonify
import requests
import hashlib
import json
import time
from threading import Thread
from datetime import datetime

app = Flask(__name__)
main_server = 'http://localhost:5000'
miner_address = None

class Miner:
    def __init__(self):
        self.chain = []
        self.pending = []
        self.node = None
        self.syncing = False
        self.last_block_index = 0

    def sync_chain(self):
        res = requests.get(f"{main_server}/chain")
        if res.status_code == 200:
            self.chain = res.json()['chain']
            self.pending = requests.get(
                f"{main_server}/tx/pending"
            ).json()

    def validate_chain(self):
        for i in range(1, len(self.chain)):
            prev = self.chain[i-1]
            curr = self.chain[i]
            
            if curr['previous_hash'] != hashlib.sha256(
                json.dumps(prev, sort_keys=True).encode()
            ).hexdigest():
                return False
            
            if not self.valid_proof(prev['proof'], curr['proof']):
                return False
        return True

    @staticmethod
    def valid_proof(last, current):
        guess = f"{last}{current}".encode()
        return hashlib.sha256(guess).hexdigest().startswith('0000')

    def print_status(self, message):
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        print(f"[{timestamp}] {message}")

    def mine(self):
        while True:
            self.sync_chain()
            
            # Check if there are new blocks from other miners
            if self.chain and self.last_block_index != self.chain[-1]['index']:
                if self.last_block_index > 0:
                    self.print_status(f"New block detected: #{self.chain[-1]['index']}")
                self.last_block_index = self.chain[-1]['index']
            
            if not self.syncing and self.pending:
                last = self.chain[-1]
                new_block = {
                    'index': len(self.chain) + 1,
                    'timestamp': time.time(),
                    'transactions': self.pending.copy(),
                    'proof': 0,
                    'previous_hash': hashlib.sha256(
                        json.dumps(last, sort_keys=True).encode()
                    ).hexdigest()
                }

                # Add block reward
                block_reward_msg = hashlib.sha256(b'Block reward').hexdigest()
                new_block['transactions'].append({
                    'sender': '0',
                    'recipient': miner_address,
                    'amount': 0.00001,
                    'message': block_reward_msg
                })

                self.print_status(f"Mining block #{new_block['index']} with {len(self.pending)} transactions...")
                
                start_time = time.time()
                attempts = 0
                while not self.valid_proof(last['proof'], new_block['proof']):
                    new_block['proof'] += 1
                    attempts += 1
                    
                    # Check for new blocks every 1000 attempts
                    if attempts % 1000 == 0:
                        self.sync_chain()
                        if self.chain[-1]['index'] != last['index']:
                            self.print_status("Block already mined by another miner. Restarting...")
                            break

                if self.valid_proof(last['proof'], new_block['proof']):
                    self.print_status(f"Block #{new_block['index']} solved! Proof: {new_block['proof']}")
                    self.print_status(f"Time taken: {time.time() - start_time:.2f} seconds")
                    self.print_status(f"Attempts: {attempts}")
                    
                    res = requests.post(
                        f"{main_server}/block/receive",
                        json=new_block
                    )
                    
                    if res.status_code == 200:
                        self.print_status(f"Block #{new_block['index']} accepted by network!")
                        self.print_status(f"Reward: 0.00001 coins added to {miner_address}")
                        self.syncing = True
                        self.sync_chain()
                        self.syncing = False
                    else:
                        self.print_status(f"Block #{new_block['index']} rejected by network")
            time.sleep(0.1)

miner = Miner()

@app.route('/receive_block', methods=['POST'])
def receive_block():
    block = request.get_json()
    miner.chain.append(block)
    miner.pending = [
        tx for tx in miner.pending
        if tx not in block['transactions'][:-1]]
    return 'Block received', 200

@app.route('/chain')
def chain():
    return jsonify(miner.chain), 200

if __name__ == '__main__':
    miner_address = input("wallet address: ")
    print('WELCOME TO KendCoin MINER')
    requests.post(f"{main_server}/nodes/register", 
        json={'node': 'http://localhost:5001'})
    miner.sync_chain()
    Thread(target=miner.mine, daemon=True).start()
    app.run(port=5001)
