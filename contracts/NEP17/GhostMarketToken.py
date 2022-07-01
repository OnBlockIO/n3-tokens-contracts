from typing import Any, List, Union, cast

from boa3.builtin import CreateNewEvent, NeoMetadata, metadata, public
from boa3.builtin.contract import Nep17TransferEvent, abort
from boa3.builtin.interop.blockchain import get_contract, Transaction
from boa3.builtin.interop.contract import call_contract, update_contract
from boa3.builtin.interop.runtime import check_witness, script_container
from boa3.builtin.interop.storage import delete, get, put
from boa3.builtin.interop.stdlib import serialize, deserialize
from boa3.builtin.type import UInt160


# -------------------------------------------
# METADATA
# -------------------------------------------
@metadata
def manifest_metadata() -> NeoMetadata:
    """
    Defines this smart contract's metadata information
    """
    meta = NeoMetadata()
    meta.author = "Vincent Geneste, Mathias Enzensberger"
    meta.description = "GhostMarket GM NEP17 contract"
    meta.email = "hello@ghostmarket.io"
    meta.supported_standards = ["NEP-17"]
    meta.source = ["https://github.com/OnBlockIO/n3-tokens-contracts/blob/master/contracts/NEP17/GhostMarketToken.py"]
    # meta.add_permission(contract='*', methods='*')
    return meta

# -------------------------------------------
# TOKEN SETTINGS
# -------------------------------------------


AUTH_ADDRESSES = b'AU'

# Supply of the token
SUPPLY_KEY = 'totalSupply'

# Symbol of the Token
TOKEN_SYMBOL = 'GM'

# Number of decimal places
TOKEN_DECIMALS = 8

# Total Supply of tokens in the system
TOKEN_TOTAL_SUPPLY = 100_000_000 * 100_000_000  # 100m total supply * 10^8 (decimals)

# Whether the smart contract was deployed or not
DEPLOYED = b'deployed'

# Whether the smart contract is paused or not
PAUSED = b'paused'


# -------------------------------------------
# Events
# -------------------------------------------

on_transfer = Nep17TransferEvent

on_auth = CreateNewEvent(
    # trigger when an address has been authorized
    [
        ('authorized', UInt160),
        ('type', int),
        ('add', bool),
    ],
    'Authorized'
)


# DEBUG_START
# -------------------------------------------
# DEBUG
# -------------------------------------------

debug = CreateNewEvent(
    [
        ('params', list),
    ],
    'Debug'
)
# DEBUG_END


# -------------------------------------------
# NEP-17 Methods
# -------------------------------------------

@public(safe=True)
def symbol() -> str:
    """
    Gets the symbols of the token.

    This string must be valid ASCII, must not contain whitespace or control characters, should be limited to uppercase
    Latin alphabet (i.e. the 26 letters used in English) and should be short (3-8 characters is recommended).
    This method must always return the same value every time it is invoked.

    :return: a short string representing symbol of the token managed in this contract.
    """
    return TOKEN_SYMBOL


@public(safe=True)
def decimals() -> int:
    """
    Gets the amount of decimals used by the token.

    E.g. 8, means to divide the token amount by 100,000,000 (10 ^ 8) to get its user representation.
    This method must always return the same value every time it is invoked.

    :return: the number of decimals used by the token.
    """
    return TOKEN_DECIMALS


@public(safe=True)
def totalSupply() -> int:
    """
    Gets the total token supply deployed in the system.

    This number must not be in its user representation. E.g. if the total supply is 10,000,000 tokens, this method
    must return 10,000,000 * 10 ^ decimals.

    :return: the total token supply deployed in the system.
    """
    return get(SUPPLY_KEY).to_int()


@public(safe=True)
def balanceOf(account: UInt160) -> int:
    """
    Get the current balance of an address

    The parameter account must be a 20-byte address represented by a UInt160.

    :param account: the account address to retrieve the balance for
    :type account: UInt160
    """
    assert validateAddress(account), "invalid address"
    debug([account])
    return get(account).to_int()


@public
def transfer(from_address: UInt160, to_address: UInt160, amount: int, data: Any) -> bool:
    """
    Transfers an amount of NEP17 tokens from one account to another

    If the method succeeds, it must fire the `Transfer` event and must return true, even if the amount is 0,
    or from and to are the same address.

    :param from_address: the address to transfer from
    :type from_address: UInt160
    :param to_address: the address to transfer to
    :type to_address: UInt160
    :param amount: the amount of NEP17 tokens to transfer
    :type amount: int
    :param data: whatever data is pertinent to the onPayment method
    :type data: Any

    :return: whether the transfer was successful
    :raise AssertionError: raised if `from_address` or `to_address` length is not 20 or if `amount` is less than zero.
    """
    assert validateAddress(from_address), "invalid from address"
    assert validateAddress(to_address), "invalid to address"
    # contract should not be paused
    assert not isPaused(), "GhostMarket contract is currently paused"
    # the parameter amount must be greater than or equal to 0. If not, this method should throw an exception.
    assert amount >= 0

    # The function MUST return false if the from account balance does not have enough tokens to spend.
    from_balance = get(from_address).to_int()
    if from_balance < amount:
        return False

    # The function should check whether the from address equals the caller contract hash.
    # If so, the transfer should be processed;
    # If not, the function should use the check_witness to verify the transfer.
    if not check_witness(from_address):
        return False

    # skip balance changes if transferring to yourself or transferring 0 cryptocurrency
    if from_address != to_address and amount != 0:
        if from_balance == amount:
            delete(from_address)
        else:
            put(from_address, from_balance - amount)

        to_balance = get(to_address).to_int()
        put(to_address, to_balance + amount)

    # if the method succeeds, it must fire the transfer event
    on_transfer(from_address, to_address, amount)
    # if the to_address is a smart contract, it must call the contracts onPayment
    post_transfer(from_address, to_address, amount, data)
    # and then it must return true
    return True


def post_transfer(from_address: Union[UInt160, None], to_address: Union[UInt160, None], amount: int, data: Any):
    """
    Checks if the one receiving NEP17 tokens is a smart contract and if it's one the onPayment method will be called

    :param from_address: the address of the sender
    :type from_address: UInt160
    :param to_address: the address of the receiver
    :type to_address: UInt160
    :param amount: the amount of cryptocurrency that is being sent
    :type amount: int
    :param data: any pertinent data that might validate the transaction
    :type data: Any
    """
    if not isinstance(to_address, None):
        contract = get_contract(to_address)
        if not isinstance(contract, None):
            call_contract(to_address, 'onNEP17Payment', [from_address, amount, data])


@public
def _deploy(data: Any, upgrade: bool):
    """
    The contracts initial entry point, on deployment.
    """
    if upgrade:
        return

    if get(DEPLOYED).to_bool():
        abort()

    if get(SUPPLY_KEY).to_int() > 0:
        abort()

    tx = cast(Transaction, script_container)
    owner: UInt160 = tx.sender

    put(DEPLOYED, True)
    put(PAUSED, False)
    put(SUPPLY_KEY, TOKEN_TOTAL_SUPPLY)
    put(owner, TOKEN_TOTAL_SUPPLY)

    auth: List[UInt160] = []
    auth.append(owner)
    serialized = serialize(auth)
    put(AUTH_ADDRESSES, serialized)

    on_transfer(None, owner, TOKEN_TOTAL_SUPPLY)
    post_transfer(None, owner, TOKEN_TOTAL_SUPPLY, None)


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


# -------------------------------------------
# GhostMarket Methods
# -------------------------------------------

@public(safe=True)
def getAuthorizedAddress() -> list[UInt160]:
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
    serialized = get(AUTH_ADDRESSES)
    auth = cast(list[UInt160], deserialize(serialized))

    return auth


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
    assert validateAddress(address), "invalid address in set auth"
    assert isinstance(authorized, bool), "authorized has to be of type bool"
    serialized = get(AUTH_ADDRESSES)
    auth = cast(list[UInt160], deserialize(serialized))

    if authorized:
        found = False
        for i in auth:
            if i == address:
                found = True
                break

        if not found:
            auth.append(address)

        put(AUTH_ADDRESSES, serialize(auth))
        on_auth(address, 0, True)
    else:
        auth.remove(address)
        put(AUTH_ADDRESSES, serialize(auth))
        on_auth(address, 0, False)


@public(safe=True)
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
def updatePause(status: bool) -> bool:
    """
    Set contract pause status.

    :param status: the status of the contract pause
    :type status: bool
    :return: the contract pause status
    :raise AssertionError: raised if witness is not verified.
    """
    assert verify(), '`acccount` is not allowed for updatePause'
    assert isinstance(status, bool), "status has to be of type bool"
    put(PAUSED, status)
    debug(['updatePause: ', get(PAUSED).to_bool()])
    return get(PAUSED).to_bool() 


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
    tx = cast(Transaction, script_container)
    for addr in auth: 
        if check_witness(addr):
            debug(["Verification successful", addr, tx.sender])
            return True

    debug(["Verification failed", addr])
    return False


def validateAddress(address: UInt160) -> bool:
    if not isinstance(address, UInt160):
        return False
    if address == 0:
        return False
    return True
