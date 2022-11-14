#!/bin/bash
echo sync policies with mainnet values
dotnet neoxp policy sync https://mainnet1.neo.coz.io:443 genesis

echo transfer x5 GAS/NEO NEP17 from genesis to owner/steve/alice
dotnet neoxp transfer 40000000 gas genesis owen
dotnet neoxp transfer 10000 gas genesis steve
dotnet neoxp transfer 10000 gas genesis alice
dotnet neoxp transfer 10000 neo genesis steve 
dotnet neoxp transfer 10000 neo genesis alice

echo deploy nep11
dotnet neoxp contract deploy --force ./contracts/NEP11/GhostMarket.NFT.nef owen
echo deploy nep17
dotnet neoxp contract deploy --force ./contracts/NEP17/GhostMarketToken.nef owen

echo transfer GM NEP-17 from owner to steve
dotnet neoxp transfer 10000 gm owen steve
echo transfer GM NEP-17 from owner to alice
dotnet neoxp transfer 10000 gm owen alice 

echo create checkpoint
dotnet neoxp checkpoint create ./checkpoints/contracts-deployed -f
