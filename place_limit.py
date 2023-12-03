import time
import json
import requests
from abi.erc20_abi import ERC20_ABI
from abi.limit_order_abi import LIMIT_ORDER_ABI
from abi.nonce_manager_abi import NONCE_MANAGER

from eth_account.messages import encode_typed_data
from web3 import Web3


INCH_BASE_URL = "https://limit-orders.1inch.io/v3.0/"
ZERO_ADDRESS = '0x0000000000000000000000000000000000000000'


w3 = Web3(Web3.HTTPProvider())  # need RPC


limit_order_contract = "0x1111111254EEB25477B68fb85Ed929f73A960582"

limit_order_contract_instance = w3.eth.contract(
    address=limit_order_contract, abi=LIMIT_ORDER_ABI)

# здесь контракты https://github.com/1inch/limit-order-protocol-utils/blob/master/src/series-nonce-manager.const.ts
series_manager_address = w3.to_checksum_address(
    '0x303389f541ff2d620e42832f180a08e767b28e10')

series_manager = w3.eth.contract(
    address=series_manager_address, abi=NONCE_MANAGER)

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


class UndefinedError(Exception):
    pass


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


def get_decimals(contract):
    return contract.functions.decimals().call()


def convert_into_wei(amount: int | float, decimal: int):
    return int(amount * 10 ** decimal)


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


def pack_args(_time, _nonce, _series, _account):
    time_shifted = _time << 216
    nonce_shifted = _nonce << 176
    series_shifted = _series << 160
    account_int = int(_account, 16)

    return account_int | series_shifted | nonce_shifted | time_shifted


def get_all_interactions(expiration, wallet_address):
    makerAssetData = '0x'
    takerAssetData = '0x'
    getMakingAmount = '0x'
    getTakingAmount = '0x'
    permit = '0x'
    preInteraction = '0x'
    postInteraction = '0x'

    nonce = series_manager.functions.nonce(
        0, limit_order_contract
    ).call()

    nonceManagerCalldata = series_manager.encodeABI(
        fn_name="timestampBelowAndNonceEquals", args=[
            pack_args(
                expiration,
                nonce,
                0,
                wallet_address
            )
        ])

    predicate = limit_order_contract_instance.encodeABI(
        fn_name="arbitraryStaticCall",
        args=[series_manager_address, nonceManagerCalldata]
    )

    return [
        makerAssetData, takerAssetData, getMakingAmount, getTakingAmount,
        predicate, permit, preInteraction, postInteraction
    ]


def get_interactions(all_interactions: list):
    interactions = "0x"
    for interaction in all_interactions:
        interactions = interactions + trim0x(interaction)

    return interactions


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

    all_interactions = get_all_interactions(expiration, wallet_address)

    order_data = {
        "salt": int(time.time()),
        "makerAsset": (Web3.to_checksum_address(token_in)),
        "takerAsset": (Web3.to_checksum_address(token_out)),
        "maker": (Web3.to_checksum_address(wallet_address)),
        "receiver": (ZERO_ADDRESS),
        "allowedSender": (ZERO_ADDRESS),
        "makingAmount": (str(amount_in_wei)),
        "takingAmount": (str(amount_out_wei)),
        "offsets": (str(getOffsets(all_interactions))),
        "interactions": (str(get_interactions(all_interactions)))
    }

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

    encoded_message = encode_typed_data(full_message=eip712_data)

    signed_message = w3.eth.account.sign_message(
        encoded_message, wallet_private_key)

    limit_order = {
        "orderHash": signed_message.messageHash.hex(),
        "signature": signed_message.signature.hex(),
        "data": order_data,
    }

    stringified = json.dumps(limit_order)
    headers = {'Content-Type': 'application/json'}

    limit_order_url = INCH_BASE_URL + str(chain_id) + "/limit-order"
    r = requests.post(limit_order_url, data=stringified, headers=headers)
    if r.status_code != 201:
        msg = r.json()['message']
        error = r.json()['error']
        raise UndefinedError(f"{msg, error}")

    return limit_order['orderHash']


# place_limit(
#     '0x55d398326f99059fF775485246999027B3197955',
#     '0xbb4CdB9CBd36B01bD1cBaEBF2De08d9173bc095c',
#     10,
#     0.043,
#     360000000000,
#     '0x2126d4C51F05159993d8f509E0172520426120a9',
#     '0x2ad6db4866f04fb2ea1ceb6f1ce3cd852ae097c8a2a014c4f65aa70aae6baa40'
# )
