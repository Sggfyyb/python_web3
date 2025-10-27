import asyncio
from web3 import AsyncWeb3
from eth_typing import ChecksumAddress,HexStr
from eth_account.signers.local import LocalAccount
from hexbytes import HexBytes
from fake_useragent import UserAgent
from curl_cffi.requests import AsyncSession
from web3.middleware import async_geth_poa_middleware

class Connector: #Async Web3 client for Ethereum-compatible blockchains.
    private_key:str
    rpc:str
    proxy:str
    account:LocalAccount
    w3:AsyncWeb3

    def __init__(self,private_key:str, rpc:str, proxy:str|None =None): #Initialize the client with a private key, RPC endpoint, and optional proxy.
        self.private_key = private_key
        self.rpc = rpc
        self.proxy = proxy

        if self.proxy: #proxy check
            if '://' not in self.proxy:
                self.proxy = f'http://{proxy}'

        # Set headers with a random user-agent
        self.headers = {
            'accept': '*/*',
            'accept-language': 'en-US,en;q=0.9',
            'content-type': 'application/json',
            'user-agent': UserAgent().chrome
        }

        ## Initialize async Web3 provider
        self.w3 = AsyncWeb3(AsyncWeb3.AsyncHTTPProvider(endpoint_uri=rpc,request_kwargs={
            'headers': self.headers,
            'proxy': self.proxy
        }))

        # Middleware for chains with Proof-of-Authority (like BSC Testnet)
        self.w3.middleware_onion.inject(async_geth_poa_middleware, layer=0)

        # Create account from private key
        self.account: LocalAccount = self.w3.eth.account.from_key(private_key)

    async def send_transaction(
            self,
            to:str|ChecksumAddress,
            from_:str|ChecksumAddress|None = None,
            value:float|None= None,
            eip_1559:bool = True,
            max_priority_fee:float|None = None,
            increase_gas: int|None = None,
            data:HexStr|None = None,

    ) -> HexBytes|None:

        if not from_:
            from_= self.account.address

        # Base transaction parameters
        tx_params ={
            'chainId': await self.w3.eth.chain_id,
            'from': AsyncWeb3.to_checksum_address(from_),
            'to': AsyncWeb3.to_checksum_address(to),
            'nonce': await self.w3.eth.get_transaction_count(self.account.address)

        }

        #checking the transaction type and estimate gas
        if eip_1559:
           if max_priority_fee:
               tx_params['maxPriorityFeePerGas'] = max_priority_fee
           else:
               max_priority_fee = await self.w3.eth.max_priority_fee
               base_fee = (await self.w3.eth.get_block('latest'))['baseFeePerGas']
               max_fee = base_fee + max_priority_fee
               tx_params['maxPriorityFeePerGas'] = max_priority_fee
               tx_params['maxFeePerGas'] = max_fee
        else:
            tx_params['gasPrice'] = await  self.w3.eth.gas_price

        if data:
            tx_params['data'] = data

        if value:
            tx_params['value'] = value
        else:
            tx_params['value'] = 0

        est_gas = await  self.w3.eth.estimate_gas(tx_params)
        tx_params['gas'] = int(est_gas * increase_gas)

        ## Sign and send the transaction
        sign = self.account.sign_transaction(tx_params)
        return await self.w3.eth.send_raw_transaction(sign.rawTransaction)

    #checking the transaction
    async def verify(self, tx_hash: HexBytes, timeout:float = 300):
        data = await self.w3.eth.wait_for_transaction_receipt(transaction_hash=tx_hash,timeout=timeout)
        if data.get('status') ==1:
            print(f'Transaction{tx_hash.hex()} is succeeded')
        else:
            raise Exception(f'Transaction {data["transactionHash"].hex()} is failed ')

    @staticmethod
    #receiving the token price
    async def token_price(token_symbol= 'ETH'):
        token_symbol = token_symbol.upper()

        if token_symbol == 'WETH':
            token_symbol = 'ETH'
        if token_symbol == 'WBTC':
            token_symbol = 'BTC'

        if token_symbol in ('USDC', 'USDT', 'DAI', 'CEBUSD', 'BUSD', 'USDC.E'):
            return 1
        for _ in range(6):
            try:
                async with AsyncSession() as session:
                    response =  await session.get(f'https://api.binance.com/api/v3/depth?limit=1&symbol={token_symbol}USDT')
                    result_dict =  response.json()
                    if 'asks' not  in result_dict:
                        return
                    return float(result_dict['asks'][0][0])
            except Exception:
                await asyncio.sleep(5)
        raise ValueError(f'Unable to find cost at this time {token_symbol}')

