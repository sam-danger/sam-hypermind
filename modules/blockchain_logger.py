from web3 import Web3
import time

def write_log(event):
    print(f"[Blockchain Log] {event} - {time.ctime()}")
    # Gerçek bağlantı için:
    # w3 = Web3(Web3.HTTPProvider("https://sepolia.infura.io/v3/YOUR_API_KEY"))
    # w3.eth.send_transaction({...})
