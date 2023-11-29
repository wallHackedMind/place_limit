

import json

NONCE_MANAGER = json.loads('''
[{"inputs":[],"name":"AdvanceNonceFailed","type":"error"},{"anonymous":false,"inputs":[{"indexed":true,"internalType":"address","name":"maker","type":"address"},{"indexed":false,"internalType":"uint256","name":"series","type":"uint256"},{"indexed":false,"internalType":"uint256","name":"newNonce","type":"uint256"}],"name":"NonceIncreased","type":"event"},{"inputs":[{"internalType":"uint256","name":"series","type":"uint256"},{"internalType":"uint256","name":"amount","type":"uint256"}],"name":"advanceNonce","outputs":[],"stateMutability":"nonpayable","type":"function"},{"inputs":[{"internalType":"uint8","name":"series","type":"uint8"}],"name":"increaseNonce","outputs":[],"stateMutability":"nonpayable","type":"function"},{"inputs":[{"internalType":"uint256","name":"","type":"uint256"},{"internalType":"address","name":"","type":"address"}],"name":"nonce","outputs":[{"internalType":"uint256","name":"","type":"uint256"}],"stateMutability":"view","type":"function"},{"inputs":[{"internalType":"uint256","name":"series","type":"uint256"},{"internalType":"address","name":"makerAddress","type":"address"},{"internalType":"uint256","name":"makerNonce","type":"uint256"}],"name":"nonceEquals","outputs":[{"internalType":"bool","name":"","type":"bool"}],"stateMutability":"view","type":"function"},{"inputs":[{"internalType":"uint256","name":"time","type":"uint256"}],"name":"timestampBelow","outputs":[{"internalType":"bool","name":"","type":"bool"}],"stateMutability":"view","type":"function"},{"inputs":[{"internalType":"uint256","name":"timeNonceSeriesAccount","type":"uint256"}],"name":"timestampBelowAndNonceEquals","outputs":[{"internalType":"bool","name":"","type":"bool"}],"stateMutability":"view","type":"function"}]
''')