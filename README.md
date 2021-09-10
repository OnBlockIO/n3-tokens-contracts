# GhostMarket NFT NEP11 Contract
## Deployed Contract:

#### GhostMarket.NFT
https://dora.coz.io/contract/neo3/mainnet/0x577a51f7d39162c9de1db12a6b319c848e4c54e5

## Audit

Coming soon...

## Technical Information

Upgradable NEP11 Contract.

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



