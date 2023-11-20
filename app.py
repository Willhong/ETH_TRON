import hashlib
import base58
from flask import Flask, jsonify, request

import os
import binascii
from ecdsa import SigningKey, SECP256k1
import requests
from web3 import Web3
from tronpy.keys import PrivateKey
from tronpy import Tron, Contract
from tronpy.providers import HTTPProvider
from eth_abi import encode

application = Flask(__name__)

TRONGRID_API_KEY=""
INFURA_PROVIDER_URL=""
MAINWALLET_ADDRESS_ETH=""

def encode_params(inputs):
    types = []
    values = []

    for input in inputs:
        type = input['type']
        value = input['value']

        if type == 'address':
            if value.startswith('41'):
                value = '0x' + value[2:]
        elif type == 'address[]':
            value = ['0x' + v[2:] if v.startswith('41') else v for v in value]

        types.append(type)
        values.append(value)

    encoded_parameters = encode(types, values).hex()

    return encoded_parameters

def estimate_tron_energy(from_address, to_address,client):
    param=encode_params([
    {'type': 'address',
    'value': client.to_hex_address(to_address)},
    {'type':'uint256',
        'value':500000}
    ])
    url = "https://api.trongrid.io/walletsolidity/triggerconstantcontract"
    payload = {
        "owner_address": from_address,
        "contract_address": "TR7NHqjeKQxGTCi8q8ZY4pL8otSzgjLj6t",
        "function_selector": "transfer(address,uint256)",
        "parameter": param,
        "visible": True
    }
    headers = {
        "accept": "application/json",
        "content-type": "application/json"
    }

    response = requests.post(url, json=payload, headers=headers)

    data = response.json()
    required_energy =data["energy_used"]
    #data['result']에 'message' 가 있으면 에러
    if data.get('result').get('message')!=None and data.get('result').get('message').startswith('REVERT'):
        required_energy = 0
    return required_energy

def get_tron_energy_price():
    gasPrice_url='https://api.trongrid.io/jsonrpc'
    payload = {
        "jsonrpc" : "2.0",
        "id": 1,
        "method": "eth_gasPrice",
        "params": []
    }
    headers = {
        "accept": "application/json",
        "content-type": "application/json"
    }
    response = requests.post(gasPrice_url, json=payload, headers=headers)
    data=response.json()
    energy_cost = int(data['result'], 16)
    return energy_cost

usdt_abi=[{"constant":True,
           "inputs":[],"name":"name","outputs":[{"name":"","type":"string"}],"payable":False,"stateMutability":"view","type":"function"},{"constant":False,"inputs":[{"name":"_upgradedAddress","type":"address"}],"name":"deprecate","outputs":[],"payable":False,"stateMutability":"nonpayable","type":"function"},{"constant":False,"inputs":[{"name":"_spender","type":"address"},{"name":"_value","type":"uint256"}],"name":"approve","outputs":[],"payable":False,"stateMutability":"nonpayable","type":"function"},{"constant":True,"inputs":[],"name":"deprecated","outputs":[{"name":"","type":"bool"}],"payable":False,"stateMutability":"view","type":"function"},{"constant":False,"inputs":[{"name":"_evilUser","type":"address"}],"name":"addBlackList","outputs":[],"payable":False,"stateMutability":"nonpayable","type":"function"},{"constant":True,"inputs":[],"name":"totalSupply","outputs":[{"name":"","type":"uint256"}],"payable":False,"stateMutability":"view","type":"function"},{"constant":False,"inputs":[{"name":"_from","type":"address"},{"name":"_to","type":"address"},{"name":"_value","type":"uint256"}],
           "name":"transferFrom","outputs":[],"payable":False,"stateMutability":"nonpayable","type":"function"},{"constant":True,"inputs":[],"name":"upgradedAddress","outputs":[{"name":"","type":"address"}],"payable":False,"stateMutability":"view","type":"function"},{"constant":True,"inputs":[{"name":"","type":"address"}],"name":"balances","outputs":[{"name":"","type":"uint256"}],"payable":False,"stateMutability":"view","type":"function"},{"constant":True,"inputs":[],"name":"decimals","outputs":[{"name":"","type":"uint256"}],"payable":False,"stateMutability":"view","type":"function"},{"constant":True,"inputs":[],"name":"maximumFee","outputs":[{"name":"","type":"uint256"}],"payable":False,"stateMutability":"view","type":"function"},{"constant":True,"inputs":[],"name":"_totalSupply","outputs":[{"name":"","type":"uint256"}],"payable":False,"stateMutability":"view","type":"function"},{"constant":False,"inputs":[],"name":"unpause","outputs":[],"payable":False,"stateMutability":"nonpayable","type":"function"},{"constant":True,"inputs":[{"name":"_maker","type":"address"}],"name":"getBlackListStatus","outputs":[{"name":"","type":"bool"}],"payable":False,"stateMutability":"view","type":"function"},{"constant":True,"inputs":[{"name":"","type":"address"},{"name":"","type":"address"}],"name":"allowed","outputs":[{"name":"","type":"uint256"}],"payable":False,"stateMutability":"view","type":"function"},{"constant":True,"inputs":[],"name":"paused","outputs":[{"name":"","type":"bool"}],"payable":False,"stateMutability":"view","type":"function"},{"constant":True,"inputs":[{"name":"who","type":"address"}],"name":"balanceOf","outputs":[{"name":"","type":"uint256"}],"payable":False,"stateMutability":"view","type":"function"},{"constant":False,"inputs":[],"name":"pause","outputs":[],"payable":False,"stateMutability":"nonpayable","type":"function"},{"constant":True,"inputs":[],"name":"getOwner","outputs":[{"name":"","type":"address"}],"payable":False,"stateMutability":"view","type":"function"},{"constant":True,"inputs":[],"name":"owner","outputs":[{"name":"","type":"address"}],"payable":False,"stateMutability":"view","type":"function"},{"constant":True,"inputs":[],"name":"symbol","outputs":[{"name":"","type":"string"}],"payable":False,"stateMutability":"view","type":"function"},{"constant":False,"inputs":[{"name":"_to","type":"address"},{"name":"_value","type":"uint256"}],
           "name":"transfer","outputs":[],"payable":False,"stateMutability":"nonpayable","type":"function"},{"constant":False,"inputs":[{"name":"newBasisPoints","type":"uint256"},{"name":"newMaxFee","type":"uint256"}],"name":"setParams","outputs":[],"payable":False,"stateMutability":"nonpayable","type":"function"},{"constant":False,"inputs":[{"name":"amount","type":"uint256"}],"name":"issue","outputs":[],"payable":False,"stateMutability":"nonpayable","type":"function"},{"constant":False,"inputs":[{"name":"amount","type":"uint256"}],"name":"redeem","outputs":[],"payable":False,"stateMutability":"nonpayable","type":"function"},{"constant":True,"inputs":[{"name":"_owner","type":"address"},{"name":"_spender","type":"address"}],"name":"allowance","outputs":[{"name":"remaining","type":"uint256"}],"payable":False,"stateMutability":"view","type":"function"},{"constant":True,"inputs":[],"name":"basisPointsRate","outputs":[{"name":"","type":"uint256"}],"payable":False,"stateMutability":"view","type":"function"},{"constant":True,"inputs":[{"name":"","type":"address"}],"name":"isBlackListed","outputs":[{"name":"","type":"bool"}],"payable":False,"stateMutability":"view","type":"function"},{"constant":False,"inputs":[{"name":"_clearedUser","type":"address"}],"name":"removeBlackList","outputs":[],"payable":False,"stateMutability":"nonpayable","type":"function"},{"constant":True,"inputs":[],"name":"MAX_UINT","outputs":[{"name":"","type":"uint256"}],"payable":False,"stateMutability":"view","type":"function"},{"constant":False,"inputs":[{"name":"newOwner","type":"address"}],"name":"transferOwnership","outputs":[],"payable":False,"stateMutability":"nonpayable","type":"function"},{"constant":False,"inputs":[{"name":"_blackListedUser","type":"address"}],"name":"destroyBlackFunds","outputs":[],"payable":False,"stateMutability":"nonpayable","type":"function"},{"inputs":[{"name":"_initialSupply","type":"uint256"},{"name":"_name","type":"string"},{"name":"_symbol","type":"string"},{"name":"_decimals","type":"uint256"}],"payable":False,"stateMutability":"nonpayable","type":"constructor"},{"anonymous":False,"inputs":[{"indexed":False,"name":"amount","type":"uint256"}],"name":"Issue","type":"event"},{"anonymous":False,"inputs":[{"indexed":False,"name":"amount","type":"uint256"}],"name":"Redeem","type":"event"},{"anonymous":False,"inputs":[{"indexed":False,"name":"newAddress","type":"address"}],"name":"Deprecate","type":"event"},{"anonymous":False,"inputs":[{"indexed":False,"name":"feeBasisPoints","type":"uint256"},{"indexed":False,"name":"maxFee","type":"uint256"}],"name":"Params","type":"event"},{"anonymous":False,"inputs":[{"indexed":False,"name":"_blackListedUser","type":"address"},{"indexed":False,"name":"_balance","type":"uint256"}],"name":"DestroyedBlackFunds","type":"event"},{"anonymous":False,"inputs":[{"indexed":False,"name":"_user","type":"address"}],"name":"AddedBlackList","type":"event"},{"anonymous":False,"inputs":[{"indexed":False,"name":"_user","type":"address"}],"name":"RemovedBlackList","type":"event"},{"anonymous":False,"inputs":[{"indexed":True,"name":"owner","type":"address"},{"indexed":True,"name":"spender","type":"address"},{"indexed":False,"name":"value","type":"uint256"}],"name":"Approval","type":"event"},{"anonymous":False,"inputs":[{"indexed":True,"name":"from","type":"address"},{"indexed":True,"name":"to","type":"address"},{"indexed":False,"name":"value","type":"uint256"}],"name":"Transfer","type":"event"},{"anonymous":False,"inputs":[],"name":"Pause","type":"event"},{"anonymous":False,"inputs":[],"name":"Unpause","type":"event"}]

@application.route('/ETH/createWallet', methods=['GET'])
async def createWallet_ETH():
    try:
        private_key=binascii.hexlify(os.urandom(32)).decode('utf-8')
        print ("SAVE BUT DO NOT SHARE THIS:", private_key)

        sk = SigningKey.from_string(binascii.unhexlify(private_key), curve=SECP256k1)
        public_key =binascii.hexlify(sk.verifying_key.to_string()).decode('utf-8')
        key_bytes = binascii.unhexlify(public_key)
        keccak_hash = Web3.keccak(key_bytes)
        decapitalized_address ="0x" + binascii.hexlify(keccak_hash[-20:]).decode('utf-8')
        address=Web3.to_checksum_address(decapitalized_address)
        print("Address:", address)

        
        message = {
                'status' : 200,
                'address' :address ,
                'public_key' : public_key,
                'private_key' : private_key
            }
        respone = jsonify(message)
        respone.status_code = 200
    except Exception as e:
        message = {
                'status' : 500,
                'message' : str(e)
            }
        respone = jsonify(message)
        respone.status_code = 500
    finally:
        return respone
    
@application.route('/ETH/send/ETH/', methods=['POST'])
async def send_ETH():
    try:
        requests_data = request.get_json()
        private_key=requests_data['private_key']
        from_address=requests_data['from_address']
        to_address=MAINWALLET_ADDRESS_ETH

        print("Address:", to_address)

        wallet= Web3(Web3.HTTPProvider(INFURA_PROVIDER_URL, request_kwargs={'timeout': 60}))
        balance = wallet.eth.w3.eth.get_balance(from_address)

        gas_estimate = wallet.eth.estimate_gas({
            'from': from_address,
            'to': to_address,
            'value': balance,
        })
        gas_price = wallet.eth.gas_price
        amount = int(balance - ((gas_estimate * gas_price)*1.1))

        transaction = {
            'to': to_address,
            'from': from_address,
            'value': amount,
            'gas': gas_estimate,
            'gasPrice': gas_price,
            'nonce': wallet.eth.get_transaction_count(from_address),
        }
        gas_in_eth = Web3.from_wei(gas_price * gas_estimate *1.1, 'ether')
        signed_txn = wallet.eth.account.sign_transaction(transaction, private_key)
        tx_hash = wallet.eth.send_raw_transaction(signed_txn.rawTransaction)
        receipt = wallet.eth.wait_for_transaction_receipt(tx_hash)
        print(receipt)
        balance = wallet.eth.w3.eth.get_balance(from_address)
        balance= Web3.from_wei(balance, 'ether')
        print(balance)
        message = {
            'status' : 200,
            'address' :to_address ,
            'balance' :balance ,
            'gas_spent' : gas_in_eth,
            'tx_hash' : tx_hash.hex()

        }
        respone = jsonify(message)
    except Exception as e:
        message = {
                'status' : 500,
                'message' : str(e)
            }
        respone = jsonify(message)
        respone.status_code = 500
    finally:
        return respone
    
@application.route('/ETH/check/ETH/', methods=['POST'])
async def check_ETH():
    try:
        requests_data = request.get_json()
        from_address=requests_data['from_address']

        wallet= Web3(Web3.HTTPProvider(INFURA_PROVIDER_URL, request_kwargs={'timeout': 60}))
        balance = wallet.eth.w3.eth.get_balance(from_address)
        balance= Web3.from_wei(balance, 'ether')
        print(balance)
        # usdt_address='0xdac17f958d2ee523a2206206994597c13d831ec7'
        # usdt_address=Web3.to_checksum_address(usdt_address)
        # wallet_contract = wallet.eth.contract(usdt_address, abi=usdt_abi)
        # usdt_balance = wallet_contract.functions.balanceOf(from_address).call()

        # print(usdt_balance / 1000000)
        #return wallet address and balance
        message = {
            'status' : 200,
            'address' :from_address ,
            'eth_balance' :float(balance) ,
            # 'usdt_balance' : usdt_balance/ 1000000
        }
        respone = jsonify(message)
    except Exception as e:
        message = {
                'status' : 500,
                'message' : str(e)
            }
        respone = jsonify(message)
        respone.status_code = 500
    finally:
        return respone

@application.route('/ETH/gas', methods=['POST'])
async def gas_USDT():
    try:
        requests_data = request.get_json()
        from_address=requests_data['from_address']
        to_address= MAINWALLET_ADDRESS_ETH
        wallet= Web3(Web3.HTTPProvider(INFURA_PROVIDER_URL, request_kwargs={'timeout': 60}))
        
        balance = wallet.eth.w3.eth.get_balance(from_address)
        balance= Web3.from_wei(balance, 'ether')

        usdt_address='0xdac17f958d2ee523a2206206994597c13d831ec7'
        usdt_address=Web3.to_checksum_address(usdt_address)
        wallet_contract = wallet.eth.contract(usdt_address, abi=usdt_abi)
        usdt_balance = wallet_contract.functions.balanceOf(from_address).call()

        estimated_gas_transfer = wallet_contract.functions.transfer(to_address, usdt_balance).estimate_gas({'from': from_address})
        allowance=wallet_contract.functions.allowance(from_address, to_address).call()

        if allowance==0:
            estimated_gas_approve = wallet_contract.functions.approve(to_address, usdt_balance).estimate_gas({'from': from_address})
        else:
            estimated_gas_approve = 0

        gas_price = wallet.eth.gas_price 

        cost_in_wei_transfer = estimated_gas_transfer * gas_price
        cost_in_wei_approve = estimated_gas_approve * gas_price

        cost_in_ether_transfer = wallet.from_wei(cost_in_wei_transfer, 'ether')
        cost_in_ether_approve = wallet.from_wei(cost_in_wei_approve, 'ether')

        message = {
                'status' : 200,
                'to_address' :to_address ,
                'from_address' : from_address,
                'eth_balance' :balance ,
                'usdt_balance' : f'{usdt_balance/ 1000000}USDT',
                'estimate_gas_price_transfer' : f'{cost_in_ether_transfer}ETH',
                'estimate_gas_price_approve' : f'{cost_in_ether_approve}ETH',
                'estimate_gas_price(approve+send)' : f'{cost_in_ether_transfer+cost_in_ether_approve}ETH'
        }
        respone = jsonify(message)
    except Exception as e:
        message = {
                'status' : 500,
                'message' : str(e)
            }
        respone = jsonify(message)
        respone.status_code = 500
    finally:
        return respone

@application.route('/ETH/send/USDT/', methods=['POST'])
async def send_USDT():
    try:
        requests_data = request.get_json()
        private_key=requests_data['private_key']

        from_address=requests_data['from_address']
        to_address= MAINWALLET_ADDRESS_ETH

        print("Address:", to_address)

        wallet= Web3(Web3.HTTPProvider(INFURA_PROVIDER_URL, request_kwargs={'timeout': 60}))
        
        
        usdt_address='0xdac17f958d2ee523a2206206994597c13d831ec7'
        usdt_address=Web3.to_checksum_address(usdt_address)
        wallet_contract = wallet.eth.contract(usdt_address, abi=usdt_abi)
        usdt_balance = wallet_contract.functions.balanceOf(from_address).call()
        print(usdt_balance / 1000000)
        estimated_gas = wallet_contract.functions.transfer(to_address, usdt_balance).estimate_gas({'from': from_address})
 
        gas_price = wallet.eth.gas_price 

        cost_in_wei = estimated_gas * gas_price
        cost_in_ether = wallet.from_wei(cost_in_wei, 'ether')
        
        transaction = wallet_contract.functions.transfer(to_address, usdt_balance).build_transaction({
            'chainId': 1,
            'gas': int(estimated_gas),
            'gasPrice': int(gas_price*1.1),
            'nonce': wallet.eth.get_transaction_count(from_address),
        })
        signed_txn = wallet.eth.account.sign_transaction(transaction, private_key)

        tx_hash = wallet.eth.send_raw_transaction(signed_txn.rawTransaction)
        receipt = wallet.eth.wait_for_transaction_receipt(tx_hash)
        print(receipt)

        is_sent = wallet_contract.functions.balanceOf(from_address).call()
        balance = wallet.eth.w3.eth.get_balance(from_address)
        balance= Web3.from_wei(balance, 'ether')
        print(balance)


        message = {
                'status' : 200,
                'address' :to_address ,
                'eth_balance' :balance ,
                'transfer result' : is_sent==0,
                'estimate_gas_price(approve+send)' : cost_in_ether
        }
        respone = jsonify(message)
    except Exception as e:
        message = {
                'status' : 500,
                'message' : str(e)
            }
        respone = jsonify(message)
        respone.status_code = 500
    finally:
        return respone
    
@application.route('/ETH/approve/USDT/', methods=['POST'])
async def approve_USDT():
    try:
        requests_data = request.get_json()
        private_key=requests_data['private_key']

        from_address=requests_data['from_address']
        to_address= MAINWALLET_ADDRESS_ETH
        print("Address:", to_address)
        wallet= Web3(Web3.HTTPProvider(INFURA_PROVIDER_URL, request_kwargs={'timeout': 60}))
        
        
        usdt_address='0xdac17f958d2ee523a2206206994597c13d831ec7'
        usdt_address=Web3.to_checksum_address(usdt_address)
        wallet_contract = wallet.eth.contract(usdt_address, abi=usdt_abi)
        usdt_balance = wallet_contract.functions.balanceOf(from_address).call()
        estimated_gas = wallet_contract.functions.approve(to_address, usdt_balance).estimate_gas({'from': from_address})
        
        gas_price = wallet.eth.gas_price 
        cost_in_wei = estimated_gas * gas_price
        cost_in_ether = wallet.from_wei(cost_in_wei, 'ether')
        
        transaction = wallet_contract.functions.approve(to_address, usdt_balance).build_transaction({
            'chainId': 1,
            'gas': int(estimated_gas),
            'gasPrice': int(wallet.eth.gas_price*1.1),
            'nonce': wallet.eth.get_transaction_count(from_address),
        })
        signed_txn = wallet.eth.account.sign_transaction(transaction, private_key)

        tx_hash = wallet.eth.send_raw_transaction(signed_txn.rawTransaction)
        receipt = wallet.eth.wait_for_transaction_receipt(tx_hash)

        is_approved = wallet_contract.functions.allowance(from_address, to_address).call()
        balance = wallet.eth.w3.eth.get_balance(from_address)
        balance= Web3.from_wei(balance, 'ether')

        message = {
                'status' : 200,
                'address' :to_address ,
                'eth_balance' :balance ,
                'usdt_balance' : usdt_balance/ 1000000,
                'estimate_gas_price(approve+send)' : cost_in_ether,
                'is_approved': is_approved
        }
        respone = jsonify(message)
    except Exception as e:
        message = {
                'status' : 500,
                'message' : str(e)
            }
        respone = jsonify(message)
        respone.status_code = 500
    finally:
        return respone

@application.route('/TRON/createWallet', methods=['GET'])
async def createWallet_TRON():
    try:
        # 키 생성
        private_key = PrivateKey.random()
        print ("SAVE BUT DO NOT SHARE THIS:", private_key)

        public_key = private_key.public_key
        # 주소 생성
        address = private_key.public_key.to_base58check_address()
        print("Address:", address)

        message= {
            "private_key": private_key.hex(),
            "public_key": public_key.hex(),
            "address": address
        }
        
        
        respone = jsonify(message)
        respone.status_code = 200

        
    except Exception as e:
        message = {
                'status' : 500,
                'message' : str(e)
            }
        respone = jsonify(message)
        respone.status_code = 500
    finally:
        return respone

@application.route('/TRON/balance', methods=['POST'])
def balance_tron():
    wallet_address = request.get_json()['from_address']

    provider = HTTPProvider(api_key=TRONGRID_API_KEY)
    client = Tron(provider)
    # USDT (TRC20) 컨트랙트 주소
    contract_address = 'TR7NHqjeKQxGTCi8q8ZY4pL8otSzgjLj6t'

    cntr = client.get_contract(contract_address)
    tron_balance=client.get_account_balance(wallet_address)
    precision = cntr.functions.decimals()

    return jsonify({
        'status': 200,
        'usdt_balance': '{}{}'.format(cntr.functions.balanceOf(wallet_address) / 10 ** precision ,cntr.functions.symbol()),
        'tron_balance': '{}TRX'.format(tron_balance)
    })

@application.route('/TRON/gas/TRX', methods=['POST'])
def estimate_tron_gas():
    provider = HTTPProvider(api_key=TRONGRID_API_KEY)
    client = Tron(provider)
    from_address = request.get_json()['from_address']
    to_address = request.get_json()['to_address']

    required_energy=estimate_tron_energy(from_address, to_address,client)
    if(required_energy==0):
        return jsonify({
            'status': 500,
            'energy_used': 0,
            'energy_cost': 0,
            'energy_cost_trx' : 0,
            'total_energy_const(trx)': 0 ,
        })
    energy_cost=get_tron_energy_price()
    # 1 trx = 1,000,000 sun
    # 420 sun = 1 energy
    # 1 trx ~ 2380 energy

    return jsonify({
        'status': 200,
        'energy_used': required_energy,
        'energy_cost': energy_cost,
        'energy_cost_trx' : energy_cost/1000000,
        'total_energy_const(trx)': required_energy * (energy_cost/1000000) ,
    })

@application.route('/TRON/send/TRX', methods=['POST'])
def send_tron():
    provider = HTTPProvider(api_key=TRONGRID_API_KEY)
    client = Tron(provider)
    from_address = request.get_json()['from_address']
    to_address = request.get_json()['to_address']
    from_address_private_key = request.get_json()['from_address_private_key']
    # USDT (TRC20) 컨트랙트 주소
    contract_address = 'TR7NHqjeKQxGTCi8q8ZY4pL8otSzgjLj6t'

    cntr = client.get_contract(contract_address)
    tron_balance=client.get_account_balance('TAA1t5fV9suUgn1HrnDyUmmWiboryNPmVK')
    print('Symbol:', cntr.functions.symbol())

    precision = cntr.functions.decimals()
    usdt_balance=cntr.functions.balanceOf(from_address)
    print('Balance:', usdt_balance / 10 ** precision)

    txn = cntr.functions.transfer(to_address, int(usdt_balance)
    ).with_owner(from_address
    ).fee_limit(15_000_000_000
    ).build(
    ).sign(PrivateKey(bytes.fromhex(from_address_private_key)))
    result = client.broadcast(txn)
    print(f"result: {result}")

    return jsonify({
        'status': 200,
        'usdt_balance': '{}{}'.format(cntr.functions.balanceOf(from_address) / 10 ** precision ,cntr.functions.symbol()),
        'tron_balance': '{}TRX'.format(tron_balance)
    })

if __name__ == '__main__':
    application.run('127.0.0.1',debug=True)