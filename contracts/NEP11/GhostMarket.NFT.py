from typing import Any, Dict, List, Union, cast, MutableSequence

from boa3.builtin import CreateNewEvent, NeoMetadata, metadata, public
from boa3.builtin.contract import Nep17TransferEvent, abort
from boa3.builtin.interop.blockchain import get_contract, Transaction
from boa3.builtin.interop.contract import NEO, GAS, call_contract, destroy_contract, update_contract
from boa3.builtin.interop.runtime import notify, log, calling_script_hash, executing_script_hash, check_witness, script_container
from boa3.builtin.interop.stdlib import serialize, deserialize, base58_encode
from boa3.builtin.interop.storage import delete, get, put, find, get_context
from boa3.builtin.interop.iterator import Iterator
from boa3.builtin.interop.crypto import ripemd160, sha256
from boa3.builtin.type import UInt160, UInt256
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
    meta.supportedstandards = ["NEP-11"]
    meta.permissions = [{"contract": "*","methods": "*"}]
    return meta


# -------------------------------------------
# TOKEN SETTINGS
# -------------------------------------------

# Fee on deploy
MINT_FEE_ON_DEPLOY = 5_000_000 # initial mint fees of 0.05 GAS

# Symbol of the Token
TOKEN_SYMBOL = 'GHOST'

# Number of decimal places
TOKEN_DECIMALS = 0

# Whether the smart contract was deployed or not
DEPLOYED = b'deployed'

# Whether the smart contract is paused or not
PAUSED = b'paused'


# -------------------------------------------
# Prefixes
# -------------------------------------------

ACCOUNT_PREFIX = b'A'
TOKEN_PREFIX = b'T'
TOKEN_DATA_PREFIX = b'TD'
LOCKED_PREFIX = b'LC'
BALANCE_PREFIX = b'B'
SUPPLY_PREFIX = b'S'
META_PREFIX = b'M'
LOCKED_VIEW_COUNT_PREFIX = b'LV'
ROYALTIES_PREFIX = b'R'


# -------------------------------------------
# Keys
# -------------------------------------------

TOKEN_COUNT = b'TC'
MINT_FEE = b'F'
AUTH_ADDRESSES = b'AU'
WL_ADDRESSES = b'W'


# -------------------------------------------
# Events
# -------------------------------------------

on_transfer = CreateNewEvent(
    # trigger when tokens are transferred, including zero value transfers.
    [
        ('from_addr', Union[UInt160, None]),
        ('to_addr', Union[UInt160, None]),
        ('amount', int),
        ('tokenId', bytes)
    ],
    'Transfer'
)

on_auth = CreateNewEvent(
    # trigger when an address has been authorized/whitelisted.
    [
        ('authorized', UInt160),
        ('type', int),
        ('add', bool),
    ],
    'Authorized'
)

on_withdraw_mint_fee = CreateNewEvent(
    # trigger when mint fees are withdrawn.
    [
        ('from_addr', UInt160),
        ('value', int)
    ],
    'MintFeeWithdrawn'
)

on_update_mint_fee = CreateNewEvent(
    #trigger when mint fees are updated.
    [
        ('from_addr', UInt160),
        ('value', int)
    ],
    'MintFeeUpdated'
)

on_unlock = CreateNewEvent(
    [
        ('tokenId', bytes),
        ('counter', int)
    ],
    'UnlockIncremented'
)

#DEBUG_START
# -------------------------------------------
# DEBUG
# -------------------------------------------

debug = CreateNewEvent(
    [
        ('params', list),
    ],
    'Debug'
)
#DEBUG_END
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
    debug(['symbol: ', TOKEN_SYMBOL])
    return TOKEN_SYMBOL

@public
def decimals() -> int:
    """
    Gets the amount of decimals used by the token.

    E.g. 8, means to divide the token amount by 100,000,000 (10 ^ 8) to get its user representation.
    This method must always return the same value every time it is invoked.

    :return: the number of decimals used by the token.
    """
    debug(['decimals: ', TOKEN_DECIMALS])
    return TOKEN_DECIMALS

@public
def totalSupply() -> int:
    """
    Gets the total token supply deployed in the system.

    This number must not be in its user representation. E.g. if the total supply is 10,000,000 tokens, this method
    must return 10,000,000 * 10 ^ decimals.

    :return: the total token supply deployed in the system.
    """
    debug(['totalSupply: ', get(SUPPLY_PREFIX).to_int()])
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
    assert len(owner) == 20, "Incorrect `owner` length"
    debug(['balanceOf: ', get(mk_balance_key(owner)).to_int()])
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
    assert len(owner) == 20, "Incorrect `owner` length"
    return find(mk_account_key(owner))

@public
def transfer(to: UInt160, tokenId: bytes, data: Any) -> bool:
    """
    Transfers the token with id tokenId to address to

    The parameter to SHOULD be a 20-byte address. If not, this method SHOULD throw an exception.
    The parameter tokenId SHOULD be a valid NFT. If not, this method SHOULD throw an exception.
    If the method succeeds, it MUST fire the Transfer event, and MUST return true, even if the token is sent to the owner.
    If the receiver is a deployed contract, the function MUST call onNEP11Payment method on receiver contract with the
    data parameter from transfer AFTER firing the Transfer event.

    The function SHOULD check whether the owner address equals the caller contract hash. If so, the transfer SHOULD be
    processed; If not, the function SHOULD use the SYSCALL Neo.Runtime.CheckWitness to verify the transfer.

    If the transfer is not processed, the function SHOULD return false.

    :param to: the address to transfer to
    :type to: UInt160
    :param tokenId: the token to transfer
    :type tokenId: ByteString
    :param data: whatever data is pertinent to the onPayment method
    :type data: Any
    :return: whether the transfer was successful
    :raise AssertionError: raised if `to` length is not 20 or if `tokenId` is not a valid NFT or if the contract is paused.
    """
    assert len(to) == 20, "Incorrect `to` length"
    assert not isPaused(), "GhostMarket contract is currently paused"
    token_owner = get_owner_of(tokenId)

    if not check_witness(token_owner):
        return False

    if (token_owner != to):
        set_balance(token_owner, -1)

        set_balance(to, 1)

        set_owner_of(tokenId, to)
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
    owner = get_owner_of(tokenId)
    debug(['ownerOf: ', owner])
    return owner

@public
def tokens() -> Iterator:
    """
    Get all tokens minted by the contract

    :return: an iterator that contains all of the tokens minted by the contract.
    """
    debug(['tokens: ', find(TOKEN_PREFIX)])
    return find(TOKEN_PREFIX)

@public
def properties(tokenId: bytes) -> bytes:
    """
    Get the properties of a token.

    The parameter tokenId SHOULD be a valid NFT. If no metadata is found (invalid tokenId), an exception is thrown.

    :param tokenId: the token for which to check the properties
    :type tokenId: ByteString
    :return: a serialized NVM object containing the properties for the given NFT.
    :raise AssertionError: raised if `tokenId` is not a valid NFT, or if no metadata available.
    """
    meta = get_meta(tokenId)
    assert len(meta) != 0, 'No metadata available for token'
    debug(['properties: ', meta])
    return meta

@public
def _deploy(data: Any, upgrade: bool):
    """
    The contracts initial entry point, on deployment.
    """
    if upgrade:
        return

    if get(DEPLOYED).to_bool():
        abort()

    tx = cast(Transaction, script_container)
#DEBUG_START
#custom owner for tests
    if tx.sender is None:
        owner = UInt160(b'\x96Wl\x0e**\x1c!\xc4\xac^\xbd)31\x15%A\x1f@')
#DEBUG_END

    put(DEPLOYED, True)
    put(PAUSED, False)
    put(TOKEN_COUNT, 0)
    put(MINT_FEE, MINT_FEE_ON_DEPLOY)

    auth: List[UInt160] = []
    auth.append(tx.sender)
    serialized = serialize(auth)
    put(AUTH_ADDRESSES, serialized)

    wl: List[UInt160] = []
    wl.append(tx.sender)
    wl_serialized = serialize(auth)
    put(WL_ADDRESSES, wl_serialized)

@public
def onNEP11Payment(from_address: UInt160, amount: int, tokenId: bytes, data: Any):
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
    if calling_script_hash != GAS:
        abort()
    debug(["onNEP17Payment", data])


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
    :raise AssertionError: raised if the contract is paused.
    """
    assert not isPaused(), "GhostMarket contract is currently paused"
    return internal_burn(tokenId)

@public
def multiBurn(tokens: List[bytes]) -> List[bool]:
    """
    Burn multiple tokens.

    :param tokens: list of tokens to burn
    :type tokens: ByteString list
    :return: whether each burn was successful, as a list.
    """
    burned: List[bool] = []
    for i in tokens:
        burned.append(burn(i))
    return burned

@public
def mint(account: UInt160, meta: bytes, lockedContent: bytes, royalties: bytes, data: Any) -> bytes:
    """
    Mint new token.

    :param account: the address of the account that is minting token
    :type account: UInt160
    :param meta: the metadata to use for this token
    :type meta: bytes
    :param lockedContent: the lock content to use for this token
    :type lockedContent: bytes
    :param royalties: the royalties to use for this token
    :type royalties: bytes
    :param data: whatever data is pertinent to the mint method
    :type data: Any
    :return: tokenId of the token minted
    :raise AssertionError: raised if mint fee is less than than 0 or if the account does not have enough to pay for it or if the contract is paused or if check witness fails.
    """
    assert not isPaused(), "GhostMarket contract is currently paused"

    fee = get_mint_fee()
    assert fee > 0, "Mint fee can't be < 0"
    assert check_witness(account), "Invalid witness" 

    if fee > 0:
        # TODO use calling_script_hash instead of account
        success: bool = call_contract(GAS, 'transfer', [account, executing_script_hash, fee, None])
        assert success, "Fee payment failed!" 

    return internal_mint(account, meta, lockedContent, royalties, data)

@public
def multiMint(account: UInt160, meta: List[bytes], lockedContent: List[bytes], royalties: List[bytes], data: Any) -> List[bytes]:
    """
    Mint new tokens.

    :param account: the address of the account that is minting tokens
    :type account: UInt160
    :param meta: the metadata to use for this token
    :type meta: bytes
    :param lockedContent: the lock content to use for this token
    :type lockedContent: bytes
    :param royalties: the royalties to use for this token
    :type royalties: bytes
    :param data: whatever data is pertinent to the mint method
    :type data: Any
    :return: list of tokenId of the tokens minted
    :raise AssertionError: raised if royalties or lockContent or meta is not a list
    """
    assert isinstance(meta, list), "meta format should be a list!"
    assert isinstance(lockedContent, list), "lock content format should be a list!"
    assert isinstance(royalties, list), "royalties format should be a list!"

    nfts: List[bytes] = []
    for i in range(0, len(meta)):
        nfts.append(mint(account, meta[i], lockedContent[i], royalties[i], data))
    return nfts

@public
def mintWhitelisted(account: UInt160, meta: bytes, lockedContent: bytes, royalties: bytes, data: Any) -> bytes:
    """
    Mint new token with no fees - whitelisted only.

    :param account: the address of the account that is minting token
    :type account: UInt160
    :param meta: the metadata to use for this token
    :type meta: bytes
    :param lockedContent: the lock content to use for this token
    :type lockedContent: bytes
    :param royalties: the royalties to use for this token
    :type royalties: bytes
    :param data: whatever data is pertinent to the mint method
    :type data: Any
    :return: tokenId of the token minted
    :raise AssertionError: raised if address is not whitelisted or if contract is paused
    """
    assert not isPaused(), "GhostMarket contract is currently paused"
    assert isWhitelisted(), '`account` is not whitelisted for mintWhitelisted'

    # TODO what about royalties handling with mintWhitelisted()
    return internal_mint(account, meta, lockedContent, royalties, data)

@public
def getRoyalties(tokenId: bytes) -> bytes:
    """
    Get a token royalties values.

    :param tokenId: the token to get royalties values
    :type tokenId: ByteString
    :return: bytes of addresses and values for this token royalties.
    :raise AssertionError: raised if any `tokenId` is not a valid NFT.
    """
    royalties = get_royalties(tokenId)
    assert len(royalties) != 0, 'No royalties available for token'
    debug(['getRoyalties: ', royalties])
    return royalties

@public
def withdrawFee(account: UInt160) -> bool:
    """
    Withdraw mint fees.

    :param account: the address of the account that is withdrawing fees
    :type account: UInt160
    :return: whether the transaction was successful.
    :emits MintFeeWithdrawn: on success emits MintFeeWithdrawn
    :raise AssertionError: raised if witness is not verified.
    """
    assert verify(), '`acccount` is not allowed for withdrawFee'
    current_balance = cast(int, call_contract(GAS, 'balanceOf', [executing_script_hash]))
    on_withdraw_mint_fee(account, current_balance)
    debug(['withdrawFee: ', current_balance])

    status: bool = call_contract(GAS, 'transfer', [executing_script_hash, account, current_balance, None])
    return status

@public
def getFeeBalance() -> Any:
    """
    Get mint fees balance.

    :return: balance of mint fees.
    """
    balance = call_contract(GAS, 'balanceOf', [executing_script_hash])
    debug(['getFeeBalance: ', balance])
    return balance

@public
def getMintFee() -> int:
    """
    Get configured mint fees value.

    :return: value of mint fees.
    """
    fee = get_mint_fee()
    debug(['getMintFee: ', fee])
    return fee

@public
def setMintFee(fee: int):
    """
    Set mint fees value.

    :param fee: fee to be used when minting
    :type fee: int
    :raise AssertionError: raised if witness is not verified.
    :emits MintFeeUpdated
    """
    assert verify(), '`acccount` is not allowed for setMintFee'
    set_mint_fee(fee)
    on_update_mint_fee(calling_script_hash, fee)

@public
def getLockedContentViewCount(tokenId: bytes) -> int:
    """
    Get lock content view count of a token.

    :param tokenId: the token to query
    :type tokenId: ByteString
    :return: number of times the lock content of this token was accessed.
    """
    debug(['getLockedContentViewCount: ', get_locked_view_counter(tokenId)])
    return get_locked_view_counter(tokenId)

@public
def getLockedContent(tokenId: bytes) -> bytes:
    """
    Get lock content of a token.

    :param tokenId: the token to query
    :type tokenId: ByteString
    :return: the lock content of this token.
    :raise AssertionError: raised if witness is not owner
    :emits UnlockIncremented
    """
    owner = get_owner_of(tokenId)

    assert check_witness(owner), "Prohibited access to locked content!"
    set_locked_view_counter(tokenId)
    
    debug(['getLockedContent: ', get_locked_content(tokenId)])
    content = get_locked_content(tokenId)
    counter = get_locked_view_counter(tokenId)
    on_unlock(tokenId, counter)
    return content

@public
def setAuthorizedAddress(address: UInt160, authorized: bool):
    """
    Configure authorized addresses.

    When this contract address is included in the transaction signature,
    this method will be triggered as a VerificationTrigger to verify that the signature is correct.
    For example, this method needs to be called when withdrawing token from the contract.

    :param address: the address of the account that is being authorized
    :type address: UInt160
    :param authorized: authorization status of this address
    :type authorized: bool
    :return: whether the transaction signature is correct
    :raise AssertionError: raised if witness is not verified.
    """
    assert verify(), '`acccount` is not allowed for setAuthorizedAddress'
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

@public
def setWhitelistedAddress(address: UInt160, authorized: bool):
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
    :raise AssertionError: raised if witness is not verified.
    """
    assert verify(), '`acccount` is not allowed for setWhitelistedAddress'
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

@public
def updatePause(status: bool) -> bool:
    """
    Set contract pause status.

    :param status: the status of the contract pause
    :type status: bool
    :return: the contract pause status
    :raise AssertionError: raised if witness is not verified.
    """
    assert verify(), '`acccount` is not allowed for updatePause'
    put(PAUSED, status)
    debug(['updatePause: ', get(PAUSED).to_bool()])
    return get(PAUSED).to_bool() 

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
        if check_witness(addr):
            debug(["Verification successful", addr])
            return True

    debug(["Verification failed", addr])
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
        if check_witness(addr):
            debug(["Verification successful", addr])
            return True

    debug(["Verification failed", addr])
    return False

@public
def isPaused() -> bool:
    """
    Get the contract pause status.

    If the contract is paused, some operations are restricted.

    :return: whether the contract is paused
    """
    debug(['isPaused: ', get(PAUSED).to_bool()])
    if get(PAUSED).to_bool():
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
    :raise AssertionError: raised if witness is not verified
    """
    assert verify(), '`acccount` is not allowed for update'
    update_contract(script, manifest) 
    debug(['update called and done'])

@public
def destroy():
    """
    Destroy the contract.

    :raise AssertionError: raised if witness is not verified
    """
    assert verify(), '`acccount` is not allowed for destroy'
    destroy_contract() 
    debug(['destroy called and done'])

def internal_burn(tokenId: bytes) -> bool:
    """
    Burn a token - internal

    :param tokenId: the token to burn
    :type tokenId: ByteString
    :return: whether the burn was successful.
    :raise AssertionError: raised if `tokenId` is not a valid NFT.
    """
    owner = get_owner_of(tokenId)

    if not check_witness(owner):
        return False

    remove_owner_of(tokenId)
    set_balance(owner, -1)
    add_to_supply(-1)
    remove_meta(tokenId)
    remove_locked_content(tokenId)
    remove_royalties(tokenId)
    
    post_transfer(owner, None, tokenId, None)
    return True

def internal_mint(account: UInt160, meta: bytes, lockedContent: bytes, royalties: bytes, data: Any) -> bytes:
    """
    Mint new token - internal

    :param account: the address of the account that is minting token
    :type account: UInt160
    :param meta: the metadata to use for this token
    :type meta: bytes
    :param lockedContent: the lock content to use for this token
    :type lockedContent: bytes
    :param royalties: the royalties to use for this token
    :type royalties: bytes
    :param data: whatever data is pertinent to the mint method
    :type data: Any
    :return: tokenId of the token minted
    :raise AssertionError: raised if meta is empty, or if contract is paused.
    """
    assert len(meta) != 0, '`meta` can not be empty'

    tokenId = get(TOKEN_COUNT).to_int() + 1
    put(TOKEN_COUNT, tokenId)
    tokenIdBytes = tokenId.to_bytes()
    
    #if data is not isinstance(data, None):             # TODO: NOT WORKING AS INTENDED
    #    add_token_data(tokenIdBytes, serialize(data))  # TODO: NOT WORKING AS INTENDED

    set_owner_of(tokenIdBytes, account)
    set_balance(account, 1)
    add_to_supply(1)

    add_meta(tokenIdBytes, meta)
    debug(['metadata: ', meta])

    if len(lockedContent) != 0:
        add_locked_content(tokenIdBytes, lockedContent)
        debug(['locked: ', lockedContent])

    if len(royalties) != 0:
        add_royalties(tokenIdBytes, royalties)
        debug(['royalties: ', royalties])

    post_transfer(None, account, tokenIdBytes, None)
    return tokenIdBytes


def get_token_data(tokenId: bytes) -> Union[bytes, None]:
    key = mk_token_data_key(tokenId)
    debug(['get_token_data: ', key, tokenId])
    val = get(key)
    return val

def add_token_data(tokenId: bytes, data: bytes):
    key = mk_token_data_key(tokenId)
    debug(['add_token_data: ', key, tokenId])
    put(key, data)

def get_owner_of(tokenId: bytes) -> UInt160:
    key = mk_token_key(tokenId)
    debug(['get_owner_of: ', key, tokenId])
    owner = get(key)
    return UInt160(owner)

def remove_owner_of(tokenId: bytes):
    key = mk_token_key(tokenId)
    debug(['remove_owner_of: ', key, tokenId])
    delete(key)

def set_owner_of(tokenId: bytes, owner: UInt160):
    key = mk_token_key(tokenId)
    debug(['set_owner_of: ', key, tokenId])
    put(key, owner)

def set_mint_fee(amount: int):
    debug(['set_mint_fee: ', amount])
    put(MINT_FEE, amount)

def add_to_supply(amount: int):
    total = totalSupply() + (amount)
    debug(['add_to_supply: ', amount])
    put(SUPPLY_PREFIX, total)

def set_balance(owner: UInt160, amount: int):
    old = balanceOf(owner)
    new = old + (amount)
    debug(['set_balance: ', amount])

    key = mk_balance_key(owner)
    if (new > 0):
        put(key, new)
    else:
        delete(key)

def get_meta(tokenId: bytes) -> bytes:
    key = mk_meta_key(tokenId)
    debug(['get_meta: ', key, tokenId])
    val = get(key)
    return val

def remove_meta(tokenId: bytes):
    key = mk_meta_key(tokenId)
    debug(['remove_meta: ', key, tokenId])
    delete(key)

def add_meta(tokenId: bytes, meta: bytes):
    key = mk_meta_key(tokenId)
    debug(['add_meta: ', key, tokenId])
    put(key, meta)

def get_locked_content(tokenId: bytes) -> bytes:
    key = mk_locked_key(tokenId)
    debug(['get_locked_content: ', key, tokenId])
    val = get(key)
    return val

def remove_locked_content(tokenId: bytes):
    key = mk_locked_key(tokenId)
    debug(['remove_locked_content: ', key, tokenId])
    delete(key)

def add_locked_content(tokenId: bytes, content: bytes):
    key = mk_locked_key(tokenId)
    debug(['add_locked_content: ', key, tokenId])
    put(key, content)

def get_royalties(tokenId: bytes) -> bytes:
    key = mk_royalties_key(tokenId)
    debug(['get_royalties: ', key, tokenId])
    val = get(key)
    return val

def add_royalties(tokenId: bytes, royalties: bytes):
    key = mk_royalties_key(tokenId)
    debug(['add_royalties: ', key, tokenId])
    put(key, royalties)

def remove_royalties(tokenId: bytes):
    key = mk_royalties_key(tokenId)
    debug(['remove_royalties: ', key, tokenId])
    delete(key)

def get_locked_view_counter(tokenId: bytes) -> int:
    key = mk_lv_key(tokenId)
    debug(['get_locked_view_counter: ', key, tokenId])
    return get(key).to_int()

def remove_locked_view_counter(tokenId: bytes):
    key = mk_lv_key(tokenId)
    debug(['remove_locked_view_counter: ', key, tokenId])
    delete(key)

def set_locked_view_counter(tokenId: bytes):
    key = mk_lv_key(tokenId)
    debug(['set_locked_view_counter: ', key, tokenId])
    count = get(key).to_int() + 1
    put(key, count)

def get_mint_fee() -> int:
    fee = get(MINT_FEE).to_int()
    debug(['get_mint_fee: ', fee])
    if fee is None:
        return 0
    return fee


## helpers

def mk_account_key(address: UInt160) -> bytes:
    return ACCOUNT_PREFIX + address

def mk_balance_key(address: UInt160) -> bytes:
    return BALANCE_PREFIX + address

def mk_token_key(tokenId: bytes) -> bytes:
    return TOKEN_PREFIX + tokenId

def mk_token_data_key(tokenId: bytes) -> bytes:
    return TOKEN_DATA_PREFIX + tokenId

def mk_meta_key(tokenId: bytes) -> bytes:
    return META_PREFIX + tokenId

def mk_locked_key(tokenId: bytes) -> bytes:
    return LOCKED_PREFIX + tokenId

def mk_royalties_key(tokenId: bytes) -> bytes:
    return ROYALTIES_PREFIX + tokenId

def mk_lv_key(tokenId: bytes) -> bytes:
    return LOCKED_VIEW_COUNT_PREFIX + tokenId
