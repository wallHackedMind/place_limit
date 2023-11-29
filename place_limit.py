import json
import os
from abi.erc20_abi import ERC20_ABI
from abi.limit_order_abi import LIMIT_ORDER_ABI
from abi.nonce_manager_abi import NONCE_MANAGER

from eth_account.messages import encode_structured_data
from web3 import Web3
import requests


INCH_BASE_URL = "https://limit-orders.1inch.io/v3.0/"
ETHERSCAN_API_KEY = "X1S12Q34CFKJQ2VEWSMK24HRYEB8CJAQHE" #


w3 = Web3(Web3.HTTPProvider("https://eth-mainnet.g.alchemy.com/v2/Wsx1UEfmXbLdIDhhn_UXThP4YlTJCD5Z"))
limit_order_contract = "0x1111111254EEB25477B68fb85Ed929f73A960582"
limit_order_contract_instance = w3.eth.contract(address=limit_order_contract, abi=LIMIT_ORDER_ABI)

chain_id = 1 

order_types = [
    {"name": "salt", "type": "uint256"},
    {"name": "makerAsset", "type": "address"},
    {"name": "takerAsset", "type": "address"},
    {"name": "maker", "type": "address"},
    {"name": "receiver", "type": "address"},
    {"name": "allowedSender", "type": "address"},
    {"name": "makingAmount", "type": "uint256"},
    {"name": "takingAmount", "type": "uint256"},
    {"name": "offsets", "type": "uint256"},
    {"name": "interactions", "type": "bytes"},
]

# WETH = "0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2"


def getOffsets(interactions):
    lenghtMap = []

    for interaction in interactions:
        if interaction[0:2] == "0x":
            lenghtMap.append(int(len(interaction)/2 - 1))
        else:
            lenghtMap.append(int(len(interaction)/2))

    cumulativeSum = 0
    bytesAccumularot = 0
    index = 0
    UINT32_BITS = 32
    for lenght in lenghtMap:
        cumulativeSum += lenght
        bytesAccumularot += cumulativeSum << (UINT32_BITS * index)
        index += 1

    offsets = bytesAccumularot
    
    return offsets


def trim0x(hexString):
    if hexString[0:2] == '0x':
        return hexString[2:]
    return hexString


def fix_data_types(data, types):
    """ 
    Order data values are all strings as this is what the API expects. This function fixes their types for    encoding purposes.  
    """

    fixed_data = {}
    for dictionary in types:
        if "bytes" in dictionary["type"]:
            fixed_data[dictionary["name"]] = (
                Web3.to_bytes(hexstr=data[dictionary["name"]]))
        elif "int" in dictionary["type"]:
            fixed_data[dictionary["name"]] = int(data[dictionary["name"]])

        else:
            fixed_data[dictionary["name"]] = data[dictionary["name"]]

    return fixed_data


def generate_salt() -> int:
    buffer = os.urandom(32)
    sliced_bytes = ''.join(format(byte, '02x') for byte in buffer)
    return int(sliced_bytes, 16)


# def get_token_abi(address: str):
#     r = requests.get(f"https://api.etherscan.io/api?module=contract&action=getabi&address={address}&apikey={ETHERSCAN_API_KEY}")
#     if not r.status_code == 200:
#         # TODO: HANDLE 
#         print(f"something wrong while fetching abi for {address}")
    
#     abi = r.json()['result']
#     return json.loads(abi)
     


def get_decimals(contract):
    return contract.functions.decimals().call()


def convert_into_wei(amount: int | float, decimal: int):
    return int(amount * decimal ** 18)


def perform_convert_into_wei(
        token: str,
        amount: float | int,
):

    contract = w3.eth.contract(
        address=Web3.to_checksum_address(token),
        abi=ERC20_ABI
    )
    
    decimals = get_decimals(contract)

    return convert_into_wei(amount, decimals)


def get_all_interactions(expiration):
    makerAssetData = '0x'
    takerAssetData = '0x'
    getMakingAmount = '0x'
    getTakingAmount = '0x'
    permit = '0x'
    preInteraction = '0x'
    postInteraction = '0x'

    series = 0 #

    # https://github.com/1inch/limit-order-protocol-utils/blob/fdbb559509eeb6e22e2697cccb22887d69617652/src/series-nonce-manager.const.ts
    seriesNonceManagerContractAddress = w3.to_checksum_address(
        '0x303389f541ff2d620e42832f180a08e767b28e10')
    seriesNonceManagerInstance = w3.eth.contract(
        address=seriesNonceManagerContractAddress, abi=NONCE_MANAGER)

    nonceManagerCalldata = seriesNonceManagerInstance.encodeABI(
        fn_name="timestampBelow", args=[expiration])

    predicate = limit_order_contract_instance.encodeABI(
        fn_name="arbitraryStaticCall",
        args=[seriesNonceManagerContractAddress, nonceManagerCalldata]
    )

    print(nonceManagerCalldata, 'nonceManagerCalldata')
    print(predicate, 'predicate')

    return [
        makerAssetData, takerAssetData, getMakingAmount, getTakingAmount,
        predicate, permit, preInteraction, postInteraction
    ]


def get_interactions(all_interactions: list):
    interactions = "0x"
    for interaction in all_interactions:
        interactions += trim0x(interaction)
        

    return interactions


def get_tx_hash(order_hash: str):
    url = INCH_BASE_URL + str(chain_id) + f'/events/{order_hash}'


    r = requests.get(url)

    if r.status_code != 200:
        print(r.text, r.status_code, 'error get_tx_hash')
        print(r.json(), 'error get_tx_hash ')
        print(
            f"Error while fetching tx hash. Status code:{r.status_code}, error: {r.json()['error']}, msg: {r.json()['message']}")

    #TODO: REMOVE
    print(r.json(), 'hahs tx')
    return r.json()[order_hash][0]['transactionHash']


def place_limit(
        token_in: str,
        token_out: str,
        amount_in: float | int,
        amount_out: float | int,
        expiration: int,
        wallet_address: str,
        wallet_private_key: str,
):

    amount_in_wei = perform_convert_into_wei(token_in, amount_in)
    amount_out_wei = perform_convert_into_wei(token_out, amount_out)

    print(amount_in_wei, amount_out_wei, 'converted to wei')

    all_interactions = get_all_interactions(expiration)

    print(all_interactions, 'all_interactions')



    order_data = {
        "salt": str(generate_salt()),
        "makerAsset": Web3.to_checksum_address(token_in),
        "takerAsset": Web3.to_checksum_address(token_out),
        "maker": Web3.to_checksum_address(wallet_address),
        "receiver": Web3.to_checksum_address(wallet_address),
        "allowedSender": "0x0000000000000000000000000000000000000000",
        "makingAmount": str(amount_in_wei),
        "takingAmount": str(amount_out_wei),
        "offsets": str(getOffsets(all_interactions)),
        "interactions": get_interactions(all_interactions)
    }

    print(order_data, 'order_data')

    eip712_data = {
        "primaryType": "Order",
        "types": {
            "EIP712Domain":
            [{"name": "name", "type": "string"},
             {"name": "version", "type": "string"},
             {"name": "chainId", "type": "uint256"},
             {"name": "verifyingContract", "type": "address"},
             ],
            "Order": order_types
        },
        "domain": {
            "name": "1inch Aggregation Router",
            "version": "5",
            "chainId": chain_id,
            "verifyingContract": "0x1111111254eeb25477b68fb85ed929f73a960582", },
        
        "message": fix_data_types(order_data, order_types), 
        
        
        }

    # eip712_data['message'] = fix_data_types(order_data, order_types)

    encoded_message = encode_structured_data(eip712_data)
    signed_message = w3.eth.account.sign_message(
        encoded_message, wallet_private_key)


    limit_order = {
        "orderHash": signed_message.messageHash.hex(),
        "signature": signed_message.signature.hex(),
        "data": order_data,
    }

    print(limit_order, 'limit_order')

   
    limit_order_url = INCH_BASE_URL + str(chain_id) + "/limit-order"
    r = requests.post(url=limit_order_url, headers={
                      "accept": "application/json, text/plain, */*", "content-type": "application/json"}, json=limit_order)

    if r.status_code != 201:
        msg = r.json()['message']
        error = r.json()['error']
        print(f"something wrong while posting limit order. Status: {r.status_code}, message: {r.json()['message']}, error: {r.json()['error']}")

        raise UndefinedError(msg, error)
        
    print(r.json(), r.text, 'response after post limit')

    return get_tx_hash(signed_message.messageHash.hex())

    

class UndefinedError(Exception):
    def __init__(self, message, error):
        self.message = message
        self.error = error
        super().__init__(f"UndefinedError: Message: {message}, Error: {error}")







place_limit(
    '0xdAC17F958D2ee523a2206206994597C13D831ec7',
    '0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48',
    0.12,
    0.10,
    5444440000,
    '0x2126d4C51F05159993d8f509E0172520426120a9',
    '0x2ad6db4866f04fb2ea1ceb6f1ce3cd852ae097c8a2a014c4f65aa70aae6baa40'
)


# valid
# {
#   "signature": "0xb8406ca79f313de982e927a4ca98a1751dc968ce56186854ec92a8004c701a2671b0b23bff972d81dcda081a7fcb768b1b2aa728987e005e8f47e3861a7550f71b",
#   "orderHash": "0xd6745a6bbdf1f1ac73c4f7bef54ecfc56fee1acc900bde9b00dd17f5f19a37c9",
#   "createDateTime": "2023-06-26T10:30:06.465Z",
#   "remainingMakerAmount": "809906760854554700000000000000",
#   "makerBalance": "280674481722926709367228622156",
#   "makerAllowance": "115792089237316195423570985008687907853269984665640564039457584007913129639935",
#   "data": {
#     "makerAsset": "string",
#     "takerAsset": "string",
#     "maker": "string",
#     "allowedSender": "0x0000000000000000000000000000000000000000",
#     "receiver": "0x0000000000000000000000000000000000000000",
#     "makingAmount": "string",
#     "takingAmount": "string",
#     "salt": "string",
#     "offsets": "0x",
#     "interactions": "0"
#   },
#   "makerRate": "0.000000000123471003",
#   "takerRate": "8099067608.545547000000000000",
#   "isMakerContract": false,
#   "orderInvalidReason": null
# }


# {
#     "signature": "0x5ee8778f6694e1b65ffbd3f5714d564fe94dce4108e4f4a6709402a504dd8c1103d974acdd882894fcc7fcde2573947bc0c21ba131e19a9e87bda61f2bd98a0a1c",
#     "orderHash": "0x0b0ad0c20b3384d2aedc7da74153c8129f102221c017f1ecbc94b01c44fb6990",
#     "createDateTime": "2023-11-28T17:36:49.415Z",
#     "remainingMakerAmount": "12187194800209",
#     "makerBalance": "206040",
#     "makerAllowance": "115792089237316195423570985008687907853269984665640564039457584007913129639935",
#     "data": {
#       "makerAsset": "0xdac17f958d2ee523a2206206994597c13d831ec7",
#       "takerAsset": "0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48",
#       "salt": "9153176104950352189759152401109214723702611672353307642439297763750690547258",
#       "receiver": "0x2126d4c51f05159993d8f509e0172520426120a9",
#       "allowedSender": "0x0000000000000000000000000000000000000000",
#       "makingAmount": "12187194800209",
#       "takingAmount": "10155995666841",
#       "maker": "0x2126d4c51f05159993d8f509e0172520426120a9",
#       "interactions": "0xbf15fcd8000000000000000000000000303389f541ff2d620e42832f180a08e767b28e100000000000000000000000000000000000000000000000000000000000000040000000000000000000000000000000000000000000000000000000000000002463592c2b0000000000000000000000000000000000000000000000000000000144838fc000000000000000000000000000000000000000000000000000000000",
#       "offsets": "4421431254442149611168492388118363282642987198110904030635476664713216"
#     },
#     "makerRate": "0.833333333333347009",
#     "takerRate": "1.199999999999980307",
#     "isMakerContract": false,
#     "orderInvalidReason": null
#   },