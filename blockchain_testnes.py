import json
from web3 import Web3
import ipfshttpclient

# Connect to IPFS
ipfs = ipfshttpclient.connect('/dns4/ipfs.infura.io/tcp/5001/https')

# Connect to Polygon Mumbai Testnet
w3 = Web3(Web3.HTTPProvider('https://polygon-mumbai.infura.io/v3/YOUR_INFURA_PROJECT_ID'))
w3.eth.default_account = w3.eth.account.privateKeyToAccount('YOUR_PRIVATE_KEY').address

# Smart contract details
contract_address = 'YOUR_CONTRACT_ADDRESS'
with open('FileBackupABI.json') as f:
    contract_abi = json.load(f)

contract = w3.eth.contract(address=contract_address, abi=contract_abi)

def backup_file_to_blockchain(filename):
    # Upload file to IPFS
    res = ipfs.add(filename)
    ipfs_hash = res['Hash']
    print(f'File uploaded to IPFS with hash: {ipfs_hash}')

    # Store IPFS hash on Polygon Mumbai Testnet
    tx = contract.functions.addFileHash(ipfs_hash).buildTransaction({
        'gas': 300000,
        'gasPrice': w3.toWei('20', 'gwei'),
        'nonce': w3.eth.getTransactionCount(w3.eth.default_account),
    })
    signed_tx = w3.eth.account.signTransaction(tx, private_key='YOUR_PRIVATE_KEY')
    tx_hash = w3.eth.sendRawTransaction(signed_tx.rawTransaction)
    receipt = w3.eth.waitForTransactionReceipt(tx_hash)
    print(f'Transaction receipt: {receipt}')

if __name__ == "__main__":
    backup_file_to_blockchain('nfc_uids.txt')
