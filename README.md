# GhostMarket NFT NEP11 Contract
## Deployed Contract:

#### GhostMarket.NFT
https://dora.coz.io/contract/neo3/mainnet/0x577a51f7d39162c9de1db12a6b319c848e4c54e5

## Audit

Coming soon...

## Technical Information

Upgradable NEP11 Contract.

## Metadata

This contract features two methods to handle properties:

`properties` and `propertiesJson`

`properties` returns a MAP of all the NFT metadata, and is what follows NEP11 standard (even though currently the standard is inconsistent as the signature shows it should be a MAP, while the explanation tied to it shows it should be a serialized NVM object).

`propertiesJson` returns a serialized JSON string of all the NFT metadata, and is what makes more sense for us to handle metadata.

This contract supports both methods for convenience purposes.

## Safe methods

Currently NEO-BOA doe not support tagging a method with a `safe` decorator. While this is optional, it is required for example if you want your NEP11 contract to use GhostMarket royalties feature, as GhostMarket trading contract checks through ABI that the `getRoyalties` is marked as `safe` to prevent potential exploits of this feature.

To do so, since BOA does not support `safe` decorator yet, simply comment the manifest file after generation, and replace the methods you want to benefit from this feature, from `safe: false` to `safe: true`

### Compiling contract
```
.compile.py
or
neo3-boa GhostMarket.NFT.py
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

tests can be run with:

```
test_ghost.py
```

individual test can be run witn  
```
python -m unittest test_ghost.GhostTest.test_ghost_decimals
```

# GhostMarket GM NEP17 Contract

## Deployed Contract:

#### GhostMarketToken
https://dora.coz.io/contract/neo3/mainnet/0x9b049f1283515eef1d3f6ac610e1595ed25ca3e9

## Audit

Coming soon...

## Technical Information

Upgradable NEP17 Contract.

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

## Testing

tests can be run with:

```
test_gm.py
```

individual test can be run witn  
```
python -m unittest test_gm.GhostTest.test_gm_decimals
```