# GhostMarket NFT NEP-11 Contract
## Deployed Contract:

#### GhostMarketNFT
https://dora.coz.io/contract/neo3/mainnet/0x577a51f7d39162c9de1db12a6b319c848e4c54e5

## Audit

Contract has been fully audited by Red4Sec.

## Technical Information

Upgradable NEP-11 Contract.

## Royalties

This contract features royalties for NFT through two standard: GhostMarket standard and NEO official standard. For each sale happening on GhostMarket trading contract, a configurable percentage will be sent to the original creator (minter) if configured (or multiple ones). For convenience sake, both are supported on this contract, and any NFT minted support both.

The details have to be passed as an array during minting, and follow a json structure.

Note that the value is in BPS (ie 10% is 1000). We support multiple royalties, up to a maximum combined of 50% royalties. Note that if a NFT has royalties, our current implementation prevent it to be traded against indivisible currencies (like NEO), but if it does not have royalties it's allowed.

[{"address":"NNau7VyBMQno89H8aAyirVJTdyLVeRxHGy","value":"1000"}] or [{"address":"NNau7VyBMQno89H8aAyirVJTdyLVeRxHGy","value":1000}]

where NNau7VyBMQno89H8aAyirVJTdyLVeRxHGy would be getting 10% of all sales as royalties.

## Metadata

This contract features two methods to handle properties:

`properties` and `propertiesJson`

`properties` returns a MAP of all the NFT metadata, and is what follows NEP-11 standard (even though currently the standard is inconsistent as the signature shows it should be a MAP, while the explanation tied to it shows it should be a serialized NVM object).

`propertiesJson` returns a serialized JSON string of all the NFT metadata, and is what makes more sense for us to handle metadata.

This contract supports both methods for convenience purposes.

### Compiling contract

```
.compile.py
or
neo3-boa GhostMarketNFT.py
```

### Deploying from neo-cli

```
open wallet <wallet path>
deploy <nef path> <manifest.path>
```

### Upgrading from neo-cli

```
open wallet <path>
update <scripthashcontract> <nef path> <manifest path> <scripthashaddress>
```

## Testing

Tests can be run with:

```
python -m unittest test_ghost
```

Individual test can be run with:

```
python -m unittest test_ghost.GhostTest.test_ghost_decimals
```

# GhostMarket GM NEP-17 Contract

## Deployed Contract:

#### GhostMarketToken
https://dora.coz.io/contract/neo3/mainnet/0x9b049f1283515eef1d3f6ac610e1595ed25ca3e9

## Audit

Contract has been fully audited by Red4Sec.

## Technical Information

Upgradable NEP-17 Contract.

### Compiling contract

```
.compile2.py
or
neo3-boa GhostMarketToken.py
```

### Deploying from neo-cli

```
open wallet <wallet path>
deploy <nef path> <manifest.path>
```

### Upgrading from neo-cli

```
open wallet <path>
update <scripthashcontract> <nef path> <manifest path> <scripthashaddress>
```

## Testing

Tests can be run with:

```
python -m unittest test_gm
```

Individual test can be run with:

```
python -m unittest test_gm.GhostTest.test_gm_decimals
```
