from typing import Any, Dict, List, Union, cast, MutableSequence

from boa3.builtin import CreateNewEvent, NeoMetadata, metadata, public
from boa3.builtin.contract import Nep17TransferEvent, abort
from boa3.builtin.interop.blockchain import get_contract, Transaction
from boa3.builtin.interop.contract import NEO, GAS, call_contract, destroy_contract, update_contract
from boa3.builtin.interop.runtime import notify, log, calling_script_hash, executing_script_hash, check_witness, script_container
from boa3.builtin.interop.binary import serialize, deserialize, base58_encode
from boa3.builtin.interop.storage import delete, get, put, find, get_context
from boa3.builtin.interop.iterator import Iterator
from boa3.builtin.interop.crypto import ripemd160, sha256
from boa3.builtin.type import UInt160, UInt256
from boa3.builtin.interop.storage.storagecontext import StorageContext
from boa3.builtin.interop.contract import CallFlags
from boa3.builtin.interop.json import json_serialize, json_deserialize



# -------------------------------------------
# METADATA
# -------------------------------------------

@metadata
def manifest_metadata() -> NeoMetadata:
    """
    Defines this smart contract's metadata information
    """
    meta = NeoMetadata()
    meta.author = "Mathias Enzensberger, Vincent Geneste"
    meta.description = "GhostMarket NFT"
    meta.email = "hello@ghostmarket.io"
    meta.supportedstandards = "NEP-11" # TODO: NOT SUPPORTED YET
    return meta


# -------------------------------------------
# TOKEN SETTINGS
# -------------------------------------------

#Fee on deploy
DEPLOY_FEE = 10000000

# Symbol of the Token
TOKEN_SYMBOL = 'GHOST'
TOKEN_SYMBOL_B = b'GHOST'

# Number of decimal places
TOKEN_DECIMALS = 0

# Whether the smart contract was deployed or not
DEPLOYED = b'deployed'


# -------------------------------------------
# Prefixes
# -------------------------------------------

ACCOUNT_PREFIX = b'A'
TOKEN_PREFIX = b'T'
LOCKED_PREFIX = b'LC'
BALANCE_PREFIX = b'B'
SUPPLY_PREFIX = b'S'
META_PREFIX = b'M'
LOCKED_VIEW_COUNT_PREFIX = b'LVC'
ROYALTIES_PREFIX= b'ROY'


# -------------------------------------------
# Keys
# -------------------------------------------

TOKEN_COUNT = b'TC'
PAUSED = b'PAUSED'
MINT_FEE = b'MINT_FEE'
AUTH_ADDRESSES = b'AUTH_ADDR'
WL_ADDRESSES = b'WL_ADDR'

# -------------------------------------------
# Events
# -------------------------------------------

on_transfer = CreateNewEvent(
    #trigger when tokens are transferred, including zero value transfers.
    [
        ('from_addr', Union[UInt160, None]),
        ('to_addr', Union[UInt160, None]),
        ('amount', int),
        ('tokenId', bytes)
    ],
    'Transfer'
)

on_auth = CreateNewEvent(
    #trigger when an address has been authorized/whitelisted.
    [
        ('authorized', UInt160),
        ('type', int),
        ('add', bool),
    ],
    'Auth'
)

on_mint = CreateNewEvent(
    #trigger when a token has been minted.
    [
        ('creator', UInt160),
        ('tokenId', bytes),
        ('tokenURI', str),
        ('externalURI', str),
        ('mint_fees', int)
    ],
    'Mint'
)

on_mint_fees_withdrawn = CreateNewEvent(
    #trigger when mint fees are withdrawn.
    [
        ('from_addr', UInt160),
        ('value', int)
    ],
    'MintFeesWithdrawn'
)

on_mint_fees_updated = CreateNewEvent(
    #trigger when mint fees are updated.
    [
        ('value', int)
    ],
    'MintFeesUpdated'
)

on_royalties_set = CreateNewEvent(
    #trigger when royalties are configured.
    [
        ('tokenId', bytes),
        ('value', str)
    ],
    'RoyaltiesSet'
)

on_deploy = CreateNewEvent(
    #trigger on contract deploy.
    [
        ('owner', UInt160),
        ('symbol', str),
    ],
    'Deploy'
)

# -------------------------------------------
# DEBUG
# -------------------------------------------

debug = CreateNewEvent(
    [
        ('params', list),
    ],
    'Debug'
)

# -------------------------------------------
# NEP-11 Methods
# -------------------------------------------

@public
def symbol() -> str:
    """
    Gets the symbols of the token.

    This string must be valid ASCII, must not contain whitespace or control characters, should be limited to uppercase
    Latin alphabet (i.e. the 26 letters used in English) and should be short (3-8 characters is recommended).
    This method must always return the same value every time it is invoked.

    :return: a short string representing symbol of the token managed in this contract.
    """
    return TOKEN_SYMBOL

@public
def decimals() -> int:
    """
    Gets the amount of decimals used by the token.

    E.g. 8, means to divide the token amount by 100,000,000 (10 ^ 8) to get its user representation.
    This method must always return the same value every time it is invoked.

    :return: the number of decimals used by the token.
    """
    return TOKEN_DECIMALS

@public
def totalSupply() -> int:
    """
    Gets the total token supply deployed in the system.

    This number must not be in its user representation. E.g. if the total supply is 10,000,000 tokens, this method
    must return 10,000,000 * 10 ^ decimals.

    :return: the total token supply deployed in the system.
    """
    return get(SUPPLY_PREFIX).to_int()

@public
def balanceOf(owner: UInt160) -> int:
    """
    Get the current balance of an address

    The parameter owner must be a 20-byte address represented by a UInt160.

    :param owner: the owner address to retrieve the balance for
    :type owner: UInt160
    :return: the total amount of tokens owned by the specified address.
    :raise AssertionError: raised if `owner` length is not 20.
    """
    assert len(owner) == 20
    return get(mk_balance_key(owner)).to_int()

@public
def tokensOf(owner: UInt160) -> Iterator:
    """
    Get all of the token ids owned by the specified address

    The parameter owner must be a 20-byte address represented by a UInt160.

    :param owner: the owner address to retrieve the tokens for
    :type owner: UInt160
    :return: an iterator that contains all of the token ids owned by the specified address.
    :raise AssertionError: raised if `owner` length is not 20.
    """
    assert len(owner) == 20
    ctx = get_context()
    return find(mk_account_prefix(owner), ctx)

@public
def transfer(to: UInt160, tokenId: bytes, data: Any) -> bool:
    """
    Transfers the token with id tokenId to address to

    The parameter to SHOULD be a 20-byte address. If not, this method SHOULD throw an exception.
    The parameter tokenId SHOULD be a valid NFT. If not, this method SHOULD throw an exception.
    The function SHOULD return false if the token that will be transferred has more than one owner.
    If the method succeeds, it MUST fire the Transfer event, and MUST return true, even if the token is sent to the owner.
    If the receiver is a deployed contract, the function MUST call onNEP11Payment method on receiver contract with the
    data parameter from transfer AFTER firing the Transfer event.

    The function SHOULD check whether the owner address equals the caller contract hash. If so, the transfer SHOULD be
    processed; If not, the function SHOULD use the SYSCALL Neo.Runtime.CheckWitness to verify the transfer.

    If the transfer is not processed, the function SHOULD return false.

    :param to: the address to transfer to
    :type to: UInt160
    :param tokenId: the token to transfer
    :type tokenId: UInt160
    :param data: whatever data is pertinent to the onPayment method
    :type data: Any

    :return: whether the transfer was successful
    :raise AssertionError: raised if `to` length is not 20 or if `tokenId` is not a valid NFT.
    :emits Transfer: on success emits Transfer
    """
    assert len(to) == 20
    ctx = get_context()
    token_owner = get_owner_of(ctx, tokenId)

    if not check_witness(token_owner):
        return False

    if (token_owner != to):
        add_to_balance(ctx, token_owner, -1)
        remove_token(ctx, token_owner, tokenId)

        add_to_balance(ctx, to, 1)
        add_token(ctx, to, tokenId)
        add_owner_of(ctx, tokenId, to)
    post_transfer(token_owner, to, tokenId, data)
    return True

def post_transfer(token_owner: Union[UInt160, None], to: Union[UInt160, None], tokenId: bytes, data: Any):
    """
    Checks if the one receiving NEP11 tokens is a smart contract and if it's one the onPayment method will be called - internal

    :param token_owner: the address of the sender
    :type token_owner: UInt160
    :param to: the address of the receiver
    :type to: UInt160
    :param tokenId: the token hash as bytes
    :type tokenId: bytes
    :param data: any pertinent data that might validate the transaction
    :type data: Any
    """
    on_transfer(token_owner, to, 1, tokenId)
    if not isinstance(to, None):    # TODO: change to 'is not None' when `is` semantic is implemented
        contract = get_contract(to)
        if not isinstance(contract, None):      # TODO: change to 'is not None' when `is` semantic is implemented
            call_contract(to, 'onNEP11Payment', [token_owner, 1, tokenId, data])
            pass


@public
def ownerOf(tokenId: bytes) -> UInt160:
    """
    Get the owner of the specified token.

    The parameter tokenId SHOULD be a valid NFT. If not, this method SHOULD throw an exception.

    :param tokenId: the token for which to check the ownership
    :type tokenId: ByteString
    :return: the owner of the specified token.
    :raise AssertionError: raised if `tokenId` is not a valid NFT.
    """
    ctx = get_context()
    owner = get_owner_of(ctx, tokenId)
    return owner

@public
def tokens() -> Iterator:
    """
    Get all tokens minted by the contract

    :return: an iterator that contains all of the tokens minted by the contract.
    """
    ctx = get_context()
    return find(TOKEN_PREFIX, ctx)

@public
def properties(tokenId: bytes) -> Dict[str, str]:
    """
    Get the properties of a token.

    The parameter tokenId SHOULD be a valid NFT. If no metadata is found (invalid tokenId), an exception is thrown.

    :param tokenId: the token for which to check the properties
    :type tokenId: ByteString
    :return: a serialized NVM object containing the properties for the given NFT.
    :raise AssertionError: raised if `tokenId` is not a valid NFT.
    """
    ctx = get_context()
    meta = get_meta(ctx, tokenId)
    debug(['meta: ', meta])
    if len(meta) == 0:
        raise Exception('Unable to parse metadata')
    deserialized = json_deserialize(meta)
    debug(['deserialized: ', deserialized])
    return cast(dict[str, str], deserialized)

@public
def _deploy(data: Any, upgrade: bool):
    """
    The contracts initial entry point, on deployment.

    : 
    """
    if upgrade:
        return

    if get(DEPLOYED).to_bool():
        abort()

    owner = calling_script_hash
    # TODO calling_script_hash is null on TestEngine
    if owner is None:
        owner = UInt160(b'\x96Wl\x0e**\x1c!\xc4\xac^\xbd)31\x15%A\x1f@')

    put(DEPLOYED, True)
    put(TOKEN_COUNT, 0)
    put(MINT_FEE, DEPLOY_FEE)

    auth: List[UInt160] = []
    auth.append(owner)
    serialized = serialize(auth)
    put(AUTH_ADDRESSES, serialized)
    put(WL_ADDRESSES, serialized)

    on_deploy(owner, symbol())

@public
def onNEP11Payment(from_address: UInt160, amount: int, token: bytes, data: Any):
    """
    :param from_address: the address of the one who is trying to send cryptocurrency to this smart contract
    :type from_address: UInt160
    :param amount: the amount of cryptocurrency that is being sent to the this smart contract
    :type amount: int
    :param token: the token hash as bytes
    :type token: bytes
    :param data: any pertinent data that might validate the transaction
    :type data: Any
    """
    abort()

@public
def onNEP17Payment(from_address: UInt160, amount: int, data: Any):
    """
    :param from_address: the address of the one who is trying to send cryptocurrency to this smart contract
    :type from_address: UInt160
    :param amount: the amount of cryptocurrency that is being sent to the this smart contract
    :type amount: int
    :param data: any pertinent data that might validate the transaction
    :type data: Any
    """
    #Use calling_script_hash to identify if the incoming token is NEO or GAS
    if calling_script_hash != GAS:
        abort()

# -------------------------------------------
# GhostMarket Methods
# -------------------------------------------

@public
def burn(tokenId: bytes) -> bool:
    """
    Burn a token.

    :param tokenId: the token to burn
    :type tokenId: ByteString
    :return: whether the burn was successful.
    :raise AssertionError: raised if `tokenId` is not a valid NFT.
    """
    return internal_burn(tokenId)

@public
def multiBurn(tokens: List[bytes]) -> List[bool]:
    """
    Burn multiple tokens.

    :param tokens: list of tokens to burn
    :type tokens: ByteString list
    :return: whether each burn was successful, as a list.
    :raise AssertionError: raised if any `tokenId` is not a valid NFT.
    """
    burned: List[bool] = []
    for i in tokens:
        burned.append(burn(i))
    return burned

@public
def mint(account: UInt160, meta: str, lockedContent: bytes, royalties: str, data: Any) -> bytes:
    """
    Mint new token.

    :param account: the address of the account that is minting token
    :type account: UInt160
    :param meta: the metadata to use for this token
    :type meta: str
    :param lockedContent: the lock content to use for this token
    :type lockedContent: bytes
    :param royalties: the royalties to use for this token
    :type royalties: str
    :param data: whatever data is pertinent to the mint method
    :type data: Any
    :raise AssertionError: raised if mint fee is less than than 0 or if the account does not have enough to pay for it
    """
    ctx = get_context()
    fee = get_mint_fee(ctx)
    if fee < 0:
        raise Exception("Mint fee can't be < 0")

    if fee > 0:
        call_contract(GAS, 'transfer', [account, executing_script_hash, fee, None])
        #result = call_contract(GAS, 'transfer', [account, executing_script_hash, fee, None])
        #if not cast(bool, result):
        #    raise Exception("Fee payment failed!")

    return internal_mint(account, meta, lockedContent, royalties, data)

@public
def multiMint(account: UInt160, meta: List[str], lockedContent: List[bytes], royalties: List[str], data: Any) -> List[bytes]:
    """
    Mint new tokens.

    :param account: the address of the account that is minting tokens
    :type account: UInt160
    :param meta: the metadata to use for this token
    :type meta: str
    :param lockedContent: the lock content to use for this token
    :type lockedContent: bytes
    :param royalties: the royalties to use for this token
    :type royalties: str
    :param data: whatever data is pertinent to the mint method
    :type data: Any
    :raise AssertionError: raised if mint fee is less than than 0 or if the account does not have enough to pay for it
    or if lockContent or meta is not a list
    """
    if not isinstance(lockedContent, list):
        raise Exception("lock content format should be a list!")
    if not isinstance(meta, list):
        raise Exception("meta format should be a list!")
    if not isinstance(royalties, list):
        raise Exception("royalties format should be a list!")

    nfts: List[bytes] = []
    for i in range(0, len(meta)):
        nfts.append(mint(account, meta[i], lockedContent[i], royalties[i], data))
    return nfts

@public
def mintWithURI(account: UInt160, meta: str, lockedContent: bytes, royalties: str, data: Any) -> bytes:
    """
    Mint new token with no fees - whitelisted only.

    :param account: the address of the account that is minting token
    :type account: UInt160
    :param meta: the metadata to use for this token
    :type meta: str
    :param lockedContent: the lock content to use for this token
    :type lockedContent: bytes
    :param data: whatever data is pertinent to the mint method
    :type data: Any
    :raise AssertionError: raised if address is not whitelisted
    """
    assert isWhitelisted()

    # TODO what about royalties handling with mintWithURI()
    return internal_mint(account, meta, lockedContent, royalties, data)

@public
def getRoyalties(token: bytes) -> dict[str, int]:
    """
    Get a token royalties values.

    :param tokenId: the token to get royalties values
    :type tokenId: ByteString
    :return: dictionnary of addresses and values for this token royalties.
    """
    ctx = get_context()
    serialized = get_royalties(ctx, token)
    return cast(dict[str, int], json_deserialize(serialized))

@public
def withdrawFee(account: UInt160) -> bool:
    """
    Withdraw mint fees.

    :param account: the address of the account that is withdrawing fees
    :type account: UInt160
    :return: whether the transaction was successful.
    :raise AssertionError: raised if witness is not owner
    :emits MintFeesWithdrawn: on success emits MintFeesWithdrawn
    """
    assert verify()
    current_balance = cast(int, call_contract(GAS, 'balanceOf', [executing_script_hash]))
    on_mint_fees_withdrawn(account, current_balance)
    return cast(bool, call_contract(GAS, 'transfer', [executing_script_hash, account, current_balance, None]))

@public
def getFeeBalance() -> Any:
    """
    Get mint fees balance.

    :return: balance of mint fees.
    """
    balance = call_contract(GAS, 'balanceOf', [executing_script_hash])
    return balance

@public
def getMintFee() -> int:
    """
    Get configured mint fees value.

    :return: configured value of mint fees.
    """
    ctx = get_context()
    fee = get_mint_fee(ctx)
    return fee

@public
def setMintFee(fee: int) -> int:
    """
    Set mint fees value.

    :param fee: fee to be used when minting
    :type fee: int
    :return: configured value of mint fees.
    :raise AssertionError: raised if witness is not owner
    :emits MintFeesUpdated: on success emits MintFeesUpdated
    """
    assert verify()
    ctx = get_context()
    on_mint_fees_updated(fee)
    return set_mint_fee(ctx, fee)

@public
def getLockedContentViewCount(tokenId: bytes) -> int:
    """
    Get lock content view count of a token.

    :param tokenId: the token to query
    :type tokenId: ByteString
    :return: number of times the lock content of this token was accessed.
    """
    ctx = get_context()
    return get_locked_view_counter(ctx, tokenId)

@public
def getLockedContent(tokenId: bytes) -> bytes:
    """
    Get lock content of a token.

    :param tokenId: the token to query
    :type tokenId: ByteString
    :return: the lock content of this token.
    :raise AssertionError: raised if witness is not owner
    """
    ctx = get_context()
    owner = get_owner_of(ctx, tokenId)

    if not check_witness(owner):
        raise Exception("Prohibited access to locked content!")
    incr_locked_view_counter(ctx, tokenId)
    
    return get_locked_content(ctx, tokenId)

@public
def setAuthorizedAddress(address: UInt160, authorized: bool) -> bool:
    """
    Configure authorizated addresses.

    When this contract address is included in the transaction signature,
    this method will be triggered as a VerificationTrigger to verify that the signature is correct.
    For example, this method needs to be called when withdrawing token from the contract.

    :param address: the address of the account that is being authorized
    :type address: UInt160
    :param authorized: authorization status of this address
    :type authorized: bool
    :return: whether the transaction signature is correct
    """
    if not verify():
        return False

    serialized = get(AUTH_ADDRESSES)
    auth = cast(list[UInt160], deserialize(serialized))

    if authorized:
        found = False
        for i in auth:
            if i == address:
                found = True

        if not found:
            auth.append(address)

        put(AUTH_ADDRESSES, serialize(auth))
        on_auth(address, 0, True)
    else:
        auth.remove(address)
        put(AUTH_ADDRESSES, serialize(auth))
        on_auth(address, 0, False)

    return True

@public
def setWhitelistedAddress(address: UInt160, authorized: bool) -> bool:
    """
    Configure whitelisted addresses.

    When this contract address is included in the transaction signature,
    this method will be triggered as a VerificationTrigger to verify that the signature is correct.
    For example, this method needs to be called when using the no fee mint method.

    :param address: the address of the account that is being authorized
    :type address: UInt160
    :param authorized: authorization status of this address
    :type authorized: bool
    :return: whether the transaction signature is correct
    """
    if not verify():
        return False

    serialized = get(WL_ADDRESSES)
    auth = cast(list[UInt160], deserialize(serialized))

    if authorized:
        found = False
        for i in auth:
            if i == address:
                found = True

        if not found:
            auth.append(address)

        put(WL_ADDRESSES, serialize(auth))
        on_auth(address, 1, True)
    else:
        auth.remove(address)
        put(WL_ADDRESSES, serialize(auth))
        on_auth(address, 1, False)

    return True

@public
def verify() -> bool:
    """
    Check if the address is allowed.

    When this contract address is included in the transaction signature,
    this method will be triggered as a VerificationTrigger to verify that the signature is correct.
    For example, this method needs to be called when withdrawing token from the contract.

    :return: whether the transaction signature is correct
    """
    serialized = get(AUTH_ADDRESSES)
    auth = cast(list[UInt160], deserialize(serialized))
    for addr in auth: 
        debug(["Verifying", addr])
        if check_witness(addr):
            return True

    return False

@public
def isWhitelisted() -> bool:
    """
    Check if the address is allowed to mint without fees.

    If the address is whitelisted, it's allowed to mint without any fees.

    :return: whether the address is allowed to mint without fees
    """
    serialized = get(WL_ADDRESSES)
    auth = cast(list[UInt160], deserialize(serialized))
    for addr in auth: 
        debug(["Verifying", addr])
        if check_witness(addr):
            return True

    return False

@public
def update(script: bytes, manifest: bytes):
    """
    Upgrade the contract.

    :param script: the contract script
    :type script: bytes
    :param manifest: the contract manifest
    :type manifest: bytes
    :raise AssertionError: raised if witness is not owner
    """
    assert verify()
    update_contract(script, manifest) 

@public
def destroy():
    """
    Destroy the contract.

    :raise AssertionError: raised if witness is not owner
    """
    assert verify()
    destroy_contract() 
    debug(['destroy called and done'])

def internal_burn(token: bytes) -> bool:
    """
    Burn a token - internal

    :param tokenId: the token to burn
    :type tokenId: ByteString
    :return: whether the burn was successful.
    :raise AssertionError: raised if `tokenId` is not a valid NFT.
    """
    ctx = get_context()
    owner = get_owner_of(ctx, token)

    if not check_witness(owner):
        return False

    remove_token(ctx, owner, token)
    remove_meta(ctx, token)
    remove_locked_content(ctx, token)
    remove_owner_of(ctx, token)
    add_to_balance(ctx, owner, -1)
    add_to_supply(ctx, -1)
    
    post_transfer(owner, None, token, None)
    return True

def internal_mint(account: UInt160, meta: str, lockedContent: bytes, royalties: str, data: Any) -> bytes:
    """
    Mint new token - internal

    :param account: the address of the account that is minting token
    :type account: UInt160
    :param meta: the metadata to use for this token
    :type meta: str
    :param lockedContent: the lock content to use for this token
    :type lockedContent: bytes
    :param royalties: the royalties to use for this token
    :type royalties: str
    :param data: whatever data is pertinent to the mint method
    :type data: Any
    :raise AssertionError: raised if mint fee is less than than 0 or if the account does not have enough to pay for it
    """
    ctx = get_context()
    newNFT = bytearray(TOKEN_SYMBOL_B)
    nftData = 0
    token_id = get(TOKEN_COUNT, ctx).to_int() + 1
    put(TOKEN_COUNT, token_id, ctx)
    tx = cast(Transaction, script_container)
    nftData = nftData + tx.hash.to_int() + token_id

    if not isinstance(data, None):      # TODO: change to 'is not None' when `is` semantic is implemented
        nftData = nftData + serialize(data).to_int()
    newNFT.append(nftData)

    token = newNFT
    add_token(ctx, account, token)
    add_owner_of(ctx, token, account)
    add_to_balance(ctx, account, 1)
    add_to_supply(ctx, 1)

    nftmeta = json_serialize(meta)
    add_meta(ctx, token, nftmeta)
    debug(['nftmeta: ', nftmeta])

    add_locked_content(ctx, token, lockedContent)
    debug(['locked: ', lockedContent])

    royalties_bytes = json_serialize(royalties)
    add_royalties(ctx, token, royalties_bytes)
    on_royalties_set(token, royalties)
    debug(['royalties: ', royalties])

    post_transfer(None, account, token, None)
    return token

def get_meta(ctx: StorageContext, token: bytes) -> bytes:
    key = mk_meta_key(token)
    val = get(key, ctx)
    return val

def remove_meta(ctx: StorageContext, token: bytes):
    key = mk_meta_key(token)
    debug(['remove meta: ', key, token])
    delete(key, ctx)

def add_meta(ctx: StorageContext, token: bytes, meta: bytes):
    key = mk_meta_key(token)
    debug(['add meta: ', key, token])
    put(key, meta, ctx)

def remove_token(ctx: StorageContext, owner: UInt160, token: bytes):
    key = mk_account_prefix(owner) + token
    debug(['remove token: ', key, token])
    delete(key, ctx)

def add_token(ctx: StorageContext, owner: UInt160, token: bytes):
    key = mk_account_prefix(owner) + token
    debug(['add token: ', key, token])
    put(key, token, ctx)

def get_owner_of(ctx: StorageContext, token: bytes) -> UInt160:
    key = mk_token_key(token)
    owner = get(key, ctx)
    return UInt160(owner)

def remove_owner_of(ctx: StorageContext, token: bytes):
    key = mk_token_key(token)
    debug(['remove owner of: ', key, token])
    delete(key, ctx)

def add_owner_of(ctx: StorageContext, token: bytes, owner: UInt160):
    key = mk_token_key(token)
    debug(['set owner of: ', key, token])
    put(key, owner, ctx)

def get_royalties(ctx: StorageContext, token: bytes) -> bytes:
    key = mk_royalties_key(token)
    debug(['get royalties for token', key, token])
    val = get(key, ctx)
    return val

def add_royalties(ctx: StorageContext, token: bytes, royalties: bytes):
    key = mk_royalties_key(token)
    debug(['add royalties for token', key, token])
    put(key, royalties, ctx)

def get_locked_content(ctx: StorageContext, token: bytes) -> bytes:
    key = mk_locked_key(token)
    val = get(key, ctx)
    return val

def remove_locked_content(ctx: StorageContext, token: bytes):
    key = mk_locked_key(token)
    debug(['remove locked content: ', key, token])
    delete(key, ctx)

def add_locked_content(ctx: StorageContext, token: bytes, content: bytes):
    key = mk_locked_key(token)
    debug(['add locked content: ', key, token])
    put(key, content, ctx)

def get_mint_fee(ctx: StorageContext) -> int:
    fee = get(MINT_FEE, ctx).to_int()
    if fee is None:
        return 0
    return fee

def set_mint_fee(ctx: StorageContext, amount: int) -> int:
    put(MINT_FEE, amount, ctx)
    debug(['set mint fee: ', amount])
    return get_mint_fee(ctx)

def get_locked_view_counter(ctx: StorageContext, token: bytes) -> int:
    key = mk_lv_key(token)
    debug(['get locked view counter: ', key, token])
    return get(key, ctx).to_int()

def remove_locked_view_counter(ctx: StorageContext, token: bytes):
    key = mk_lv_key(token)
    debug(['remove locked view counter: ', key, token])
    delete(key, ctx)

def incr_locked_view_counter(ctx: StorageContext, token: bytes):
    key = mk_lv_key(token)
    count = get(key, ctx).to_int() + 1
    debug(['incr locked view counter: ', key, token])
    put(key, count)

def add_to_supply(ctx: StorageContext, amount: int):
    total = totalSupply() + (amount)
    debug(['add to supply: ', amount])
    put(SUPPLY_PREFIX, total)

def add_to_balance(ctx: StorageContext, owner: UInt160, amount: int):
    old = balanceOf(owner)
    new = old + (amount)
    debug(['add to balance: ', amount])

    key = mk_balance_key(owner)
    if (new > 0):
        put(key, new, ctx)
    else:
        delete(key, ctx)

## helpers

def mk_account_prefix(address: UInt160) -> bytes:
    return ACCOUNT_PREFIX + address

def mk_balance_key(address: UInt160) -> bytes:
    return BALANCE_PREFIX + address

def mk_royalties_key(token: bytes) -> bytes:
    return ROYALTIES_PREFIX + token


def mk_token_key(token: bytes) -> bytes:
    return TOKEN_PREFIX + token

def mk_locked_key(token: bytes) -> bytes:
    return LOCKED_PREFIX + token

def mk_meta_key(token: bytes) -> bytes:
    return META_PREFIX + token

def mk_lv_key(token: bytes) -> bytes:
    return LOCKED_VIEW_COUNT_PREFIX + token
