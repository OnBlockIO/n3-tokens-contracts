from typing import Dict
from pathlib import Path
from boa3_test.tests.boa_test import BoaTest
from boa3_test.tests.test_classes.testengine import TestEngine
from boa3.neo.smart_contract.VoidType import VoidType
from boa3.neo.cryptography import hash160
from boa3.constants import GAS_SCRIPT
from boa3.neo.vm.type.String import String
from boa3.boa3 import Boa3
from boa3.neo import to_script_hash, to_hex_str, from_hex_str
from boa3.builtin.type import UInt160
from boa3.builtin.interop.iterator import Iterator
from boa3_test.tests.test_classes.TestExecutionException import TestExecutionException
from boa3.neo.core.types.InteropInterface import InteropInterface


class GhostTest(BoaTest):
    p = Path(__file__)
    GHOST_ROOT = str(p.parents[1])
    PRJ_ROOT = str(p.parents[2])

    CONTRACT_PATH_JSON = GHOST_ROOT+ '/contracts/NEP11/GhostMarket.NFT.manifest.json'
    CONTRACT_PATH_NEF = GHOST_ROOT + '/contracts/NEP11/GhostMarket.NFT.nef'
    CONTRACT_PATH_PY = GHOST_ROOT + '/contracts/NEP11/GhostMarket.NFT.py'
    # TODO add .env file and move test engine path there
    TEST_ENGINE_PATH = '/home/merl/source/n3_gm/neo-devpack-dotnet/src/Neo.TestEngine/bin/Debug/net5.0/'
    BOA_PATH = PRJ_ROOT + '/neo3-boa/boa3'
    OWNER_SCRIPT_HASH = UInt160(to_script_hash(b'NZcuGiwRu1QscpmCyxj5XwQBUf6sk7dJJN'))
    OTHER_ACCOUNT_1 = UInt160(to_script_hash(b'NiNmXL8FjEUEs1nfX9uHFBNaenxDHJtmuB'))
    OTHER_ACCOUNT_2 = bytes(range(20))
    TOKEN_META = bytes('{ "name": "GHOST", "description": "A ghost shows up", "image": "{some image URI}", "tokenURI": "{some URI}" }', 'utf-8')
    LOCK_CONTENT = bytes('lockedContent', 'utf-8')
    ROYALTIES = bytes('[{"address": "someaddress", "value": 20}, {"address": "someaddress2", "value": 30}]', 'utf-8')

    def build_contract(self, preprocess=False):
        print('contract path: ' + self.CONTRACT_PATH_PY)
        if preprocess:
            import os
            old = os.getcwd()
            os.chdir(self.GHOST_ROOT)
            file = self.GHOST_ROOT + '/compile.py'
            os.system(file)
            os.chdir(old)
        else:
            output, manifest = self.compile_and_save(self.CONTRACT_PATH_PY)

    def deploy_contract(self, engine):
        engine.add_contract(self.CONTRACT_PATH_NEF.replace('.py', '.nef'))
        result = self.run_smart_contract(engine, self.CONTRACT_PATH_NEF, '_deploy', None, False,
                                         signer_accounts=[self.OWNER_SCRIPT_HASH],
                                         expected_result_type=bool)
        self.assertEqual(VoidType, result)

    def prepare_testengine(self, preprocess=False) -> TestEngine:
        self.build_contract(preprocess)
        engine = TestEngine(self.TEST_ENGINE_PATH)
        engine.reset_engine()
        self.deploy_contract(engine)
        return engine

    def print_notif(self, notifications):
        print('\n=========================== NOTIFICATIONS START ===========================\n')
        for notif in notifications:
            print(f"{str(notif.name)}: {str(notif.arguments)}")
        print('\n=========================== NOTIFICATIONS END ===========================\n')

    def test_ghost_compile(self):
        self.build_contract()

    def test_ghost_symbol(self):
        engine = self.prepare_testengine()
        result = engine.run(self.CONTRACT_PATH_NEF, 'symbol', reset_engine=True)
        self.print_notif(engine.notifications)

        assert isinstance(result, str)
        assert result == 'GHOST'

    def test_ghost_decimals(self):
        engine = self.prepare_testengine()
        result = engine.run(self.CONTRACT_PATH_NEF, 'decimals', reset_engine=True)
        self.print_notif(engine.notifications)

        assert isinstance(result, int)
        assert result == 0

    def test_ghost_total_supply(self):
        engine = self.prepare_testengine()
        result = engine.run(self.CONTRACT_PATH_NEF, 'totalSupply', reset_engine=True)
        self.print_notif(engine.notifications)

        assert isinstance(result, int)
        assert result == 0

    def test_ghost_deploy(self):
        engine = self.prepare_testengine()
        # prepare_testengine already deploys the contract and verifies it's successfully deployed

        # must always return false after first execution
        with self.assertRaises(TestExecutionException, msg=self.ABORTED_CONTRACT_MSG):
            result = self.run_smart_contract(engine, self.CONTRACT_PATH_NEF, '_deploy', None, False,
                                             signer_accounts=[self.OWNER_SCRIPT_HASH],
                                         expected_result_type=bool)
        self.print_notif(engine.notifications)

    def test_ghost_update(self):
        engine = self.prepare_testengine()

        # updating ghost smart contract
        file_script = open(self.CONTRACT_PATH_NEF, 'rb')
        script = file_script.read()
        #print(script)
        file_script.close()

        file_manifest = open(self.CONTRACT_PATH_JSON, 'rb')
        manifest = file_manifest.read()
        #print(manifest)
        file_manifest.close()

        result = self.run_smart_contract(engine, self.CONTRACT_PATH_NEF, 'update', 
                                         script, manifest,
                                         signer_accounts=[self.OWNER_SCRIPT_HASH],
                                         expected_result_type=bool)
        self.assertEqual(VoidType, result)

    def test_ghost_destroy(self):
        engine = self.prepare_testengine()

        # destroy contract
        result = self.run_smart_contract(engine, self.CONTRACT_PATH_NEF, 'destroy',
                                         signer_accounts=[self.OWNER_SCRIPT_HASH],
                                         expected_result_type=bool)

        # should not exist anymore
        result = self.run_smart_contract(engine, self.CONTRACT_PATH_NEF, 'symbol')
        # self.assertNotEqual('GHOST', result)

        self.print_notif(engine.notifications)

    def test_ghost_verify(self):
        engine = self.prepare_testengine()

        # should fail because account does not have enough for fees
        with self.assertRaises(TestExecutionException, msg=self.ASSERT_RESULTED_FALSE_MSG):
            self.run_smart_contract(engine, self.CONTRACT_PATH_NEF, 'verify', self.OTHER_ACCOUNT_1)

        self.print_notif(engine.notifications)

    def test_ghost_authorize(self):
        engine = self.prepare_testengine()
        self.run_smart_contract(engine, self.CONTRACT_PATH_NEF, 'setAuthorizedAddress', 
                self.OTHER_ACCOUNT_1, True,
                signer_accounts=[self.OWNER_SCRIPT_HASH],
                expected_result_type=bool)
        auth_events = engine.get_events('Authorized')

        # check if the event was triggered and the address was authorized
        self.assertEqual(0, auth_events[0].arguments[1])
        self.assertEqual(1, auth_events[0].arguments[2])

        # now deauthorize the address
        self.run_smart_contract(engine, self.CONTRACT_PATH_NEF, 'setAuthorizedAddress', 
                self.OTHER_ACCOUNT_1, False,
                signer_accounts=[self.OWNER_SCRIPT_HASH],
                expected_result_type=bool)
        auth_events = engine.get_events('Authorized')
        # check if the event was triggered and the address was authorized
        self.assertEqual(0, auth_events[1].arguments[1])
        self.assertEqual(0, auth_events[1].arguments[2])

    def test_ghost_whitelist(self):
        engine = self.prepare_testengine()
        self.run_smart_contract(engine, self.CONTRACT_PATH_NEF, 'setWhitelistedAddress', 
                self.OTHER_ACCOUNT_1, True,
                signer_accounts=[self.OWNER_SCRIPT_HASH],
                expected_result_type=bool)
        auth_events = engine.get_events('Authorized')

        # check if the event was triggered and the address was authorized
        self.assertEqual(1, auth_events[0].arguments[1])
        self.assertEqual(1, auth_events[0].arguments[2])

        # now deauthorize the address
        self.run_smart_contract(engine, self.CONTRACT_PATH_NEF, 'setWhitelistedAddress', 
                self.OTHER_ACCOUNT_1, False,
                signer_accounts=[self.OWNER_SCRIPT_HASH],
                expected_result_type=bool)
        auth_events = engine.get_events('Authorized')
        # check if the event was triggered and the address was authorized
        self.assertEqual(1, auth_events[1].arguments[1])
        self.assertEqual(0, auth_events[1].arguments[2])

    def test_ghost_pause(self):
        engine = self.prepare_testengine()
        engine.add_contract(self.CONTRACT_PATH_NEF.replace('.py', '.nef'))
        aux_path = self.get_contract_path('test_native', 'auxiliary_contract.py')
        output, manifest = self.compile_and_save(self.CONTRACT_PATH_NEF.replace('.nef', '.py'))
        ghost_address = hash160(output)
        print(to_hex_str(ghost_address))
        output, manifest = self.compile_and_save(aux_path)
        aux_address = hash160(output)
        print(to_hex_str(aux_address))

        # when deploying, the contract will mint tokens to the owner
        deploy_event = engine.get_events('Deployed')
        self.assertEqual(1, len(deploy_event))
        self.assertEqual(2, len(deploy_event[0].arguments))

        # add some gas for fees
        add_amount = 10 * 10 ** 8
        engine.add_gas(aux_address, add_amount)

        # pause contract
        fee = self.run_smart_contract(engine, self.CONTRACT_PATH_NEF, 'updatePause', True,
                signer_accounts=[self.OWNER_SCRIPT_HASH],
                expected_result_type=int)

        # should fail because contract is paused
        with self.assertRaises(TestExecutionException, msg=self.ASSERT_RESULTED_FALSE_MSG):
            token = self.run_smart_contract(engine, self.CONTRACT_PATH_NEF, 'mint', 
                    aux_address, self.TOKEN_META, self.LOCK_CONTENT, self.ROYALTIES, None,
                    signer_accounts=[aux_address],
                    expected_result_type=bytes)

        # unpause contract
        fee = self.run_smart_contract(engine, self.CONTRACT_PATH_NEF, 'updatePause', False,
                signer_accounts=[self.OWNER_SCRIPT_HASH],
                expected_result_type=int)

        # mint
        token = self.run_smart_contract(engine, self.CONTRACT_PATH_NEF, 'mint', 
            aux_address, self.TOKEN_META, self.LOCK_CONTENT, self.ROYALTIES, None,
            signer_accounts=[aux_address],
            expected_result_type=bytes)
        self.print_notif(engine.notifications)

    def test_ghost_mint(self):
        engine = self.prepare_testengine()
        engine.add_contract(self.CONTRACT_PATH_NEF.replace('.py', '.nef'))
        aux_path = self.get_contract_path('test_native', 'auxiliary_contract.py')
        output, manifest = self.compile_and_save(self.CONTRACT_PATH_NEF.replace('.nef', '.py'))
        ghost_address = hash160(output)
        print(to_hex_str(ghost_address))
        output, manifest = self.compile_and_save(aux_path)
        aux_address = hash160(output)
        print(to_hex_str(aux_address))

        # when deploying, the contract will mint tokens to the owner
        deploy_event = engine.get_events('Deployed')
        self.assertEqual(1, len(deploy_event))
        self.assertEqual(2, len(deploy_event[0].arguments))

        # should fail because account does not have enough for fees
        with self.assertRaises(TestExecutionException, msg=self.ASSERT_RESULTED_FALSE_MSG):
            self.run_smart_contract(engine, self.CONTRACT_PATH_NEF, 'mint', 
                # aux_address, self.TOKEN_META, self.LOCK_CONTENT, self.ROYALTIES, None,
                aux_address, bytes(0), bytes(0), bytes(0), None,
                signer_accounts=[aux_address],
                expected_result_type=bytes)

        # add some gas for fees
        add_amount = 10 * 10 ** 8
        engine.add_gas(aux_address, add_amount)

        # should succeed now that account has enough fees
        token = self.run_smart_contract(engine, self.CONTRACT_PATH_NEF, 'mint', 
                aux_address, self.TOKEN_META, self.LOCK_CONTENT, self.ROYALTIES, None,
                signer_accounts=[aux_address],
                expected_result_type=bytes)

        print("get props now: ")
        properties = self.run_smart_contract(engine, self.CONTRACT_PATH_NEF, 'properties', token, expected_result_type=bytes)
        print("props: " + str(properties))
        royalties = self.run_smart_contract(engine, self.CONTRACT_PATH_NEF, 'getRoyalties', token, expected_result_type=bytes)
        print("royalties: " + str(royalties))

        print('non existing props:')
        with self.assertRaises(TestExecutionException, msg='An unhandled exception was thrown. Unable to parse metadata'):
            properties = self.run_smart_contract(engine, self.CONTRACT_PATH_NEF, 'properties',
                    bytes('thisisanonexistingtoken', 'utf-8'), expected_result_type=bytes)
        print("props: " + str(properties))

        # check balances after
        ghost_amount_after = self.run_smart_contract(engine, GAS_SCRIPT, 'balanceOf', ghost_address)
        gas_aux_after = self.run_smart_contract(engine, GAS_SCRIPT, 'balanceOf', aux_address)
        print("ghost gas amount: " + str(ghost_amount_after))
        print("aux gas amount: " + str(gas_aux_after))
        ghost_balance_after = self.run_smart_contract(engine, self.CONTRACT_PATH_NEF, 'balanceOf', aux_address)
        print("balance nft: " + str(ghost_balance_after))
        ghost_supply_after = self.run_smart_contract(engine, self.CONTRACT_PATH_NEF, 'totalSupply')
        print("supply nft: " + str(ghost_supply_after))
        self.assertEqual(1, ghost_supply_after)
        self.print_notif(engine.notifications)

    def test_ghost_gas_cost(self):
        engine = self.prepare_testengine()
        engine.add_contract(self.CONTRACT_PATH_NEF.replace('.py', '.nef'))
        aux_path = self.get_contract_path('test_native', 'auxiliary_contract.py')
        output, manifest = self.compile_and_save(self.CONTRACT_PATH_NEF.replace('.nef', '.py'))
        ghost_address = hash160(output)
        print(to_hex_str(ghost_address))
        output, manifest = self.compile_and_save(aux_path)
        aux_address = hash160(output)
        print(to_hex_str(aux_address))

        # add some gas for fees
        add_amount = 10 * 10 ** 8
        engine.add_gas(aux_address, add_amount)

        # mint token with no meta, no lock content, no royalties
        token = self.run_smart_contract(engine, self.CONTRACT_PATH_NEF, 'mint', 
            aux_address, bytes(1), bytes(0), bytes(0), None,
            signer_accounts=[aux_address],
            expected_result_type=bytes)

        gasConsumed = str(int(engine.gas_consumed) / 10 ** 8)
        print("token with no meta, no lock content, no royalties: " + gasConsumed + " GAS")

        # mint token with meta, no lock content, no royalties
        token = self.run_smart_contract(engine, self.CONTRACT_PATH_NEF, 'mint', 
            aux_address, self.TOKEN_META, bytes(0), bytes(0), None,
            signer_accounts=[aux_address],
            expected_result_type=bytes)

        gasConsumed = str(int(engine.gas_consumed) / 10 ** 8)
        print("token with meta, no lock content, no royalties: " + gasConsumed + " GAS")

        # mint token with meta, lock content, no royalties
        token = self.run_smart_contract(engine, self.CONTRACT_PATH_NEF, 'mint', 
            aux_address, self.TOKEN_META, self.LOCK_CONTENT, bytes(0), None,
            signer_accounts=[aux_address],
            expected_result_type=bytes)

        gasConsumed = str(int(engine.gas_consumed) / 10 ** 8)
        print("token with meta, lock content, no royalties: " + gasConsumed + " GAS")

        # mint token with meta, no lock content, royalties
        token = self.run_smart_contract(engine, self.CONTRACT_PATH_NEF, 'mint', 
            aux_address, self.TOKEN_META, bytes(0), self.ROYALTIES, None,
            signer_accounts=[aux_address],
            expected_result_type=bytes)

        gasConsumed = str(int(engine.gas_consumed) / 10 ** 8)
        print("token with meta, no lock content, royalties: " + gasConsumed + " GAS")

        # mint token with meta, lock content, royalties
        token = self.run_smart_contract(engine, self.CONTRACT_PATH_NEF, 'mint', 
            aux_address, self.TOKEN_META, self.LOCK_CONTENT, self.ROYALTIES, None,
            signer_accounts=[aux_address],
            expected_result_type=bytes)

        gasConsumed = str(int(engine.gas_consumed) / 10 ** 8)
        print("token with meta, lock content, royalties: " + gasConsumed + " GAS")

        tokenMeta = bytes('{ "name": "GHOST3", "description": "A ghost shows up", "image": "{some image URI}", "name": "GHOST3", "description": "A ghost shows up", "image": "{some image URI}", "name": "GHOST3", "description": "A ghost shows up", "image": "{some image URI}", "name": "GHOST3", "description": "A ghost shows up", "image": "{some image URI}", "tokenURI": "{some URI}" }', 'utf-8')

        lockedContent = bytes('123456789101234567891012345678910123456789101234567891012345678910123456789101234567891012345678910123456789101234567891012345678910123456789101234567891012345678910123456789101234567891012345678910', 'utf-8')

        royalties = bytes('[{"address": "someaddress", "value": 20}, {"address": "someaddress2", "value": 30},{"address": "someaddress", "value": 20}, {"address": "someaddress2", "value": 30},{"address": "someaddress", "value": 20}, {"address": "someaddress2", "value": 30}]', 'utf-8')

        # mint high end token
        token = self.run_smart_contract(engine, self.CONTRACT_PATH_NEF, 'mint', 
            aux_address, tokenMeta, lockedContent, royalties, None,
            signer_accounts=[aux_address],
            expected_result_type=bytes)
            
        gasConsumed = str(int(engine.gas_consumed) / 10 ** 8)
        print("token with heavy meta, heavy lock content, heavy royalties: " + gasConsumed + " GAS")

        # get locked content
        content = self.run_smart_contract(engine, self.CONTRACT_PATH_NEF, 'getLockedContent', token,
                signer_accounts=[aux_address],
                expected_result_type=bytes)
            
        gasConsumed = str(int(engine.gas_consumed) / 10 ** 8)
        print("get locked content: " + gasConsumed + " GAS")

        # burn token
        burn = self.run_smart_contract(engine, self.CONTRACT_PATH_NEF, 'burn', token,
            signer_accounts=[aux_address],
            expected_result_type=bool)

        gasConsumed = str(int(engine.gas_consumed) / 10 ** 8)
        print("burn: " + gasConsumed + " GAS")

    def test_ghost_multi_mint(self):
        engine = self.prepare_testengine()
        engine.add_contract(self.CONTRACT_PATH_NEF.replace('.py', '.nef'))
        aux_path = self.get_contract_path('test_native', 'auxiliary_contract.py')
        output, manifest = self.compile_and_save(self.CONTRACT_PATH_NEF.replace('.nef', '.py'))
        ghost_address = hash160(output)
        print(to_hex_str(ghost_address))
        output, manifest = self.compile_and_save(aux_path)
        aux_address = hash160(output)
        print(to_hex_str(aux_address))

        # when deploying, the contract will mint tokens to the owner
        deploy_event = engine.get_events('Deployed')
        self.assertEqual(1, len(deploy_event))
        self.assertEqual(2, len(deploy_event[0].arguments))

        # add some gas for fees
        add_amount = 10 * 10 ** 8
        engine.add_gas(aux_address, add_amount)

        # define custom meta & lock & royalties for multi
        tokenMeta = [
                bytes('{ "name": "GHOST", "description": "A ghost shows up", "image": "{some image URI}", "tokenURI": "{some URI}" }', 'utf-8'),
                bytes('{ "name": "GHOST2", "description": "A ghost shows up", "image": "{some image URI}", "tokenURI": "{some URI}" }', 'utf-8'),
                bytes('{ "name": "GHOST3", "description": "A ghost shows up", "image": "{some image URI}", "tokenURI": "{some URI}" }', 'utf-8')
            ]

        lockedContent = [
                bytes('123', 'utf-8'),
                bytes('456', 'utf-8'),
                bytes('789', 'utf-8'),
            ]

        royalties = [
                bytes('[{"address": "someaddress", "value": 20}, {"address": "someaddress2", "value": 30}]', 'utf-8'),
                bytes('[{"address": "someaddress3", "value": 20}, {"address": "someaddress4", "value": 30}]', 'utf-8'),
                bytes('[{"address": "someaddress5", "value": 20}, {"address": "someaddress6", "value": 30}]', 'utf-8'),
            ]

        # check tokens iterator before
        ghost_tokens_before = self.run_smart_contract(engine, self.CONTRACT_PATH_NEF, 'tokens', expected_result_type=InteropInterface)
        self.assertEqual(InteropInterface, ghost_tokens_before)

        # multiMint
        result = self.run_smart_contract(engine, self.CONTRACT_PATH_NEF, 'multiMint', 
                aux_address, tokenMeta, lockedContent, royalties, None,
                signer_accounts=[aux_address],
                expected_result_type=list)
        print("result: " + str(result))

        # check tokens iterator after
        ghost_tokens_after = self.run_smart_contract(engine, self.CONTRACT_PATH_NEF, 'tokens', expected_result_type=InteropInterface)
        print("tokens after: " + str(ghost_tokens_after))
        
        # check balances after
        ghost_balance_after = self.run_smart_contract(engine, self.CONTRACT_PATH_NEF, 'balanceOf', aux_address)
        self.assertEqual(3, ghost_balance_after)
        ghost_supply_after = self.run_smart_contract(engine, self.CONTRACT_PATH_NEF, 'totalSupply')
        self.assertEqual(3, ghost_supply_after)
        self.print_notif(engine.notifications)

    def test_ghost_transfer(self):
        engine = self.prepare_testengine()
        engine.add_contract(self.CONTRACT_PATH_NEF.replace('.py', '.nef'))
        aux_path = self.get_contract_path('test_native', 'auxiliary_contract.py')
        output, manifest = self.compile_and_save(self.CONTRACT_PATH_NEF.replace('.nef', '.py'))
        ghost_address = hash160(output)
        print(to_hex_str(ghost_address))
        output, manifest = self.compile_and_save(aux_path)
        aux_address = hash160(output)
        print(to_hex_str(aux_address))

        # when deploying, the contract will mint tokens to the owner
        deploy_event = engine.get_events('Deployed')
        self.assertEqual(1, len(deploy_event))
        self.assertEqual(2, len(deploy_event[0].arguments))

        # add some gas for fees
        add_amount = 10 * 10 ** 8
        engine.add_gas(aux_address, add_amount)

        # mint
        token = self.run_smart_contract(engine, self.CONTRACT_PATH_NEF, 'mint', 
                aux_address, self.TOKEN_META, self.LOCK_CONTENT, self.ROYALTIES, None,
                signer_accounts=[aux_address],
                expected_result_type=bytes)
        properties = self.run_smart_contract(engine, self.CONTRACT_PATH_NEF, 'properties', token)
        print("props: " + str(properties))

        # check balances after
        ghost_amount_after = self.run_smart_contract(engine, GAS_SCRIPT, 'balanceOf', ghost_address)
        gas_aux_after = self.run_smart_contract(engine, GAS_SCRIPT, 'balanceOf', aux_address)
        print("ghost gas amount: " + str(ghost_amount_after))
        print("aux gas amount: " + str(gas_aux_after))
        ghost_balance_after = self.run_smart_contract(engine, self.CONTRACT_PATH_NEF, 'balanceOf', aux_address)
        print("balance nft: " + str(ghost_balance_after))
        ghost_supply_after = self.run_smart_contract(engine, self.CONTRACT_PATH_NEF, 'totalSupply')
        print("supply nft: " + str(ghost_supply_after))
        self.assertEqual(1, ghost_supply_after)

        # check owner before
        ghost_owner_of_before = self.run_smart_contract(engine, self.CONTRACT_PATH_NEF, 'ownerOf', token)
        print("owner of before: " + str(ghost_owner_of_before))

        # transfer
        result = self.run_smart_contract(engine, self.CONTRACT_PATH_NEF, 'transfer', 
                self.OTHER_ACCOUNT_1, token, None,
                signer_accounts=[aux_address],
                expected_result_type=bool)
        self.assertEqual(True, result)

        # check owner after
        ghost_owner_of_after = self.run_smart_contract(engine, self.CONTRACT_PATH_NEF, 'ownerOf', token)
        print("owner of after: " + str(ghost_owner_of_after))
        self.assertEqual(ghost_owner_of_after, self.OTHER_ACCOUNT_1)

        # check balances after
        ghost_balance_after_transfer = self.run_smart_contract(engine, self.CONTRACT_PATH_NEF, 'balanceOf', aux_address)
        ghost_supply_after_transfer = self.run_smart_contract(engine, self.CONTRACT_PATH_NEF, 'totalSupply')
        print("balance nft after transfer: " + str(ghost_balance_after_transfer))
        self.assertEqual(0, ghost_balance_after_transfer)
        self.assertEqual(1, ghost_supply_after_transfer)

        # try to transfer non existing token id
        with self.assertRaises(TestExecutionException, msg=self.ASSERT_RESULTED_FALSE_MSG):
            result = self.run_smart_contract(engine, self.CONTRACT_PATH_NEF, 'transfer', 
                    self.OTHER_ACCOUNT_1, bytes('thisisanonexistingtoken', 'utf-8'), None,
                    signer_accounts=[aux_address],
                    expected_result_type=bool)

        self.print_notif(engine.notifications)

    def test_ghost_burn(self):
        engine = self.prepare_testengine()
        engine.add_contract(self.CONTRACT_PATH_NEF.replace('.py', '.nef'))
        aux_path = self.get_contract_path('test_native', 'auxiliary_contract.py')
        output, manifest = self.compile_and_save(self.CONTRACT_PATH_NEF.replace('.nef', '.py'))
        ghost_address = hash160(output)
        print(to_hex_str(ghost_address))
        output, manifest = self.compile_and_save(aux_path)
        aux_address = hash160(output)
        print(to_hex_str(aux_address))

        # when deploying, the contract will mint tokens to the owner
        deploy_event = engine.get_events('Deployed')
        self.assertEqual(1, len(deploy_event))
        self.assertEqual(2, len(deploy_event[0].arguments))

        # add some gas for fees
        add_amount = 10 * 10 ** 8
        engine.add_gas(aux_address, add_amount)

        # mint
        token = self.run_smart_contract(engine, self.CONTRACT_PATH_NEF, 'mint', 
                aux_address, self.TOKEN_META, self.LOCK_CONTENT, self.ROYALTIES, None,
                signer_accounts=[aux_address],
                expected_result_type=bytes)

        # burn
        burn = self.run_smart_contract(engine, self.CONTRACT_PATH_NEF, 'burn', token,
                signer_accounts=[aux_address],
                expected_result_type=bool)
        print("props: " + str(burn))

        # check balances after
        ghost_balance_after = self.run_smart_contract(engine, self.CONTRACT_PATH_NEF, 'balanceOf', aux_address)
        self.assertEqual(0, ghost_balance_after)
        ghost_supply_after = self.run_smart_contract(engine, self.CONTRACT_PATH_NEF, 'totalSupply')
        self.assertEqual(0, ghost_supply_after)
        self.print_notif(engine.notifications)


    def test_ghost_multi_burn(self):
        engine = self.prepare_testengine()
        engine.add_contract(self.CONTRACT_PATH_NEF.replace('.py', '.nef'))
        aux_path = self.get_contract_path('test_native', 'auxiliary_contract.py')
        output, manifest = self.compile_and_save(self.CONTRACT_PATH_NEF.replace('.nef', '.py'))
        ghost_address = hash160(output)
        print(to_hex_str(ghost_address))
        output, manifest = self.compile_and_save(aux_path)
        aux_address = hash160(output)
        print(to_hex_str(aux_address))

        deploy_event = engine.get_events('Deployed')
        self.assertEqual(1, len(deploy_event))
        self.assertEqual(2, len(deploy_event[0].arguments))

        # add some gas for fees
        add_amount = 10 * 10 ** 8
        engine.add_gas(aux_address, add_amount)

        # define custom meta & lock & royalties for multi
        tokenMeta = [
                bytes('{ "name": "GHOST", "description": "A ghost shows up", "image": "{some image URI}", "tokenURI": "{some URI}" }', 'utf-8'),
                bytes('{ "name": "GHOST2", "description": "A ghost shows up", "image": "{some image URI}", "tokenURI": "{some URI}" }', 'utf-8'),
                bytes('{ "name": "GHOST3", "description": "A ghost shows up", "image": "{some image URI}", "tokenURI": "{some URI}" }', 'utf-8')
            ]

        lockedContent = [
                bytes('123', 'utf-8'),
                bytes('456', 'utf-8'),
                bytes('789', 'utf-8'),
            ]

        royalties = [
                bytes('[{"address": "someaddress", "value": 20}, {"address": "someaddress2", "value": 30}]', 'utf-8'),
                bytes('[{"address": "someaddress3", "value": 20}, {"address": "someaddress4", "value": 30}]', 'utf-8'),
                bytes('[{"address": "someaddress5", "value": 20}, {"address": "someaddress6", "value": 30}]', 'utf-8'),
            ]

        # multiMint
        result = self.run_smart_contract(engine, self.CONTRACT_PATH_NEF, 'multiMint', 
                aux_address, tokenMeta, lockedContent, royalties, None,
                signer_accounts=[aux_address],
                expected_result_type=list)

        # check balances after
        ghost_balance_after = self.run_smart_contract(engine, self.CONTRACT_PATH_NEF, 'balanceOf', aux_address)
        self.assertEqual(3, ghost_balance_after)
        ghost_supply_after = self.run_smart_contract(engine, self.CONTRACT_PATH_NEF, 'totalSupply')
        self.assertEqual(3, ghost_supply_after)

        # multiBurn
        burn = self.run_smart_contract(engine, self.CONTRACT_PATH_NEF, 'multiBurn', result,
                signer_accounts=[aux_address],
                expected_result_type=list)
        print("burned: " + str(burn))

        # check balances after
        ghost_balance_after = self.run_smart_contract(engine, self.CONTRACT_PATH_NEF, 'balanceOf', aux_address)
        self.assertEqual(0, ghost_balance_after)
        ghost_supply_after = self.run_smart_contract(engine, self.CONTRACT_PATH_NEF, 'totalSupply')
        self.assertEqual(0, ghost_supply_after)
        self.print_notif(engine.notifications)

    def test_ghost_onNEP11Payment(self):
        engine = self.prepare_testengine()
        engine.add_contract(self.CONTRACT_PATH_NEF.replace('.py', '.nef'))
        aux_path = self.get_contract_path('test_native', 'auxiliary_contract.py')
        output, manifest = self.compile_and_save(self.CONTRACT_PATH_NEF.replace('.nef', '.py'))
        ghost_address = hash160(output)
        print(to_hex_str(ghost_address))
        output, manifest = self.compile_and_save(aux_path)
        aux_address = hash160(output)
        print(to_hex_str(aux_address))

        # add some gas for fees
        add_amount = 10 * 10 ** 8
        engine.add_gas(self.OTHER_ACCOUNT_1, add_amount)

        # mint
        token = self.run_smart_contract(engine, self.CONTRACT_PATH_NEF, 'mint', 
            self.OTHER_ACCOUNT_1, self.TOKEN_META, self.LOCK_CONTENT, self.ROYALTIES, None,
            signer_accounts=[self.OTHER_ACCOUNT_1],
            expected_result_type=bytes)

        # the smart contract will abort if any address calls the NEP11 onPayment method
        with self.assertRaises(TestExecutionException, msg=self.ABORTED_CONTRACT_MSG):
            result = self.run_smart_contract(engine, self.CONTRACT_PATH_NEF, 'onNEP11Payment', 
                self.OTHER_ACCOUNT_1, 1, token, None,
                signer_accounts=[self.OTHER_ACCOUNT_1],
                expected_result_type=bool)

    def test_ghost_onNEP17Payment(self):
        engine = self.prepare_testengine()
        engine.add_contract(self.CONTRACT_PATH_NEF.replace('.py', '.nef'))
        aux_path = self.get_contract_path('test_native', 'auxiliary_contract.py')
        output, manifest = self.compile_and_save(self.CONTRACT_PATH_NEF.replace('.nef', '.py'))
        ghost_address = hash160(output)
        print(to_hex_str(ghost_address))
        output, manifest = self.compile_and_save(aux_path)
        aux_address = hash160(output)
        print(to_hex_str(aux_address))

        # when deploying, the contract will mint tokens to the owner
        deploy_event = engine.get_events('Deployed')
        self.assertEqual(1, len(deploy_event))
        self.assertEqual(2, len(deploy_event[0].arguments))

        # add some gas for fees
        add_amount = 10 * 10 ** 8
        engine.add_gas(aux_address, add_amount)

        # the smart contract will abort if some address other than GAS calls the NEP17 onPayment method
        with self.assertRaises(TestExecutionException, msg=self.ABORTED_CONTRACT_MSG):
            self.run_smart_contract(engine, self.CONTRACT_PATH_NEF, 'onNEP17Payment', aux_address, add_amount, None,
                                    signer_accounts=[aux_address])

    def test_ghost_mint_fee(self):
        engine = self.prepare_testengine()
        engine.add_contract(self.CONTRACT_PATH_NEF.replace('.py', '.nef'))
        output, manifest = self.compile_and_save(self.CONTRACT_PATH_NEF.replace('.nef', '.py'))
        ghost_address = hash160(output)

        # when deploying, the contract will mint tokens to the owner
        deploy_event = engine.get_events('Deployed')
        self.assertEqual(1, len(deploy_event))
        self.assertEqual(2, len(deploy_event[0].arguments))

        # add some gas for fees
        add_amount = 10 * 10 ** 8
        engine.add_gas(self.OTHER_ACCOUNT_1, add_amount/2)
        engine.add_gas(self.OWNER_SCRIPT_HASH, add_amount/2)

        # setMintFee
        fee = self.run_smart_contract(engine, self.CONTRACT_PATH_NEF, 'setMintFee', 1000,
                signer_accounts=[self.OWNER_SCRIPT_HASH],
                expected_result_type=int)

        # getMintFee should return the updated fee
        fee_event = engine.get_events('MintFeeUpdated')
        updated_fee = fee_event[0].arguments[1]
        self.assertEqual(updated_fee, 1000)

        # getMintFee should return the updated fee
        fee2 = self.run_smart_contract(engine, self.CONTRACT_PATH_NEF, 'getMintFee', expected_result_type=int)
        self.assertEqual(fee2, updated_fee)

        # fails because account not whitelisted
        with self.assertRaises(TestExecutionException, msg=self.ASSERT_RESULTED_FALSE_MSG):
            self.run_smart_contract(engine, self.CONTRACT_PATH_NEF, 'setMintFee', 1,
                                    signer_accounts=[self.OTHER_ACCOUNT_1],
                                    expected_result_type=int)

        # fees should be the same since it failed
        fee2 = self.run_smart_contract(engine, self.CONTRACT_PATH_NEF, 'getMintFee', expected_result_type=int)
        self.assertEqual(fee2, updated_fee)
        self.print_notif(engine.notifications)

    def test_ghost_fee_balance(self):
        engine = self.prepare_testengine()
        engine.add_contract(self.CONTRACT_PATH_NEF.replace('.py', '.nef'))
        output, manifest = self.compile_and_save(self.CONTRACT_PATH_NEF.replace('.nef', '.py'))
        ghost_address = hash160(output)

        # when deploying, the contract will mint tokens to the owner
        deploy_event = engine.get_events('Deployed')
        self.assertEqual(1, len(deploy_event))
        self.assertEqual(2, len(deploy_event[0].arguments))

        # add some gas for fees
        add_amount = 10 * 10 ** 8
        engine.add_gas(self.OTHER_ACCOUNT_1, add_amount)

        # check initial balance is 0
        balance = self.run_smart_contract(engine, self.CONTRACT_PATH_NEF, 'getFeeBalance',
                signer_accounts=[self.OWNER_SCRIPT_HASH],
                expected_result_type=int)
        self.assertEqual(0, balance)

        # mint + balanceOf
        token = self.run_smart_contract(engine, self.CONTRACT_PATH_NEF, 'mint', 
                self.OTHER_ACCOUNT_1, self.TOKEN_META, self.LOCK_CONTENT, self.ROYALTIES, None,
                signer_accounts=[self.OTHER_ACCOUNT_1],
                expected_result_type=bytes)
        balance_after = self.run_smart_contract(engine, self.CONTRACT_PATH_NEF, 'getFeeBalance',
                signer_accounts=[self.OWNER_SCRIPT_HASH],
                expected_result_type=int)
        initial_fee  = self.run_smart_contract(engine, self.CONTRACT_PATH_NEF, 'getMintFee', expected_result_type=int)

        # should have new balance
        self.assertEqual(initial_fee, balance_after)

        # set mint fee to 200000 + mint + getFeeBalance
        fee = self.run_smart_contract(engine, self.CONTRACT_PATH_NEF, 'setMintFee', 200000,
                signer_accounts=[self.OWNER_SCRIPT_HASH],
                expected_result_type=int)
        token = self.run_smart_contract(engine, self.CONTRACT_PATH_NEF, 'mint', 
                self.OTHER_ACCOUNT_1, self.TOKEN_META, self.LOCK_CONTENT, self.ROYALTIES, None,
                signer_accounts=[self.OTHER_ACCOUNT_1],
                expected_result_type=bytes)
        balance_after_updated = self.run_smart_contract(engine, self.CONTRACT_PATH_NEF, 'getFeeBalance',
                signer_accounts=[self.OWNER_SCRIPT_HASH],
                expected_result_type=int)
        
        # should have new balance
        self.assertEqual(balance_after_updated, balance_after + 200000)

        # withdraw fee
        success = self.run_smart_contract(engine, self.CONTRACT_PATH_NEF, 'withdrawFee', self.OWNER_SCRIPT_HASH,
                signer_accounts=[self.OWNER_SCRIPT_HASH],
                expected_result_type=int)
        self.assertEqual(True, success)

        # check balances after
        ghost_balance_after = self.run_smart_contract(engine, GAS_SCRIPT, 'balanceOf', ghost_address)
        self.assertEqual(0, ghost_balance_after)
        owner_balance = self.run_smart_contract(engine, GAS_SCRIPT, 'balanceOf', self.OWNER_SCRIPT_HASH)
        self.assertEqual(initial_fee + 200000, owner_balance)
        self.print_notif(engine.notifications)

        
    def test_ghost_locked_content(self):
        engine = self.prepare_testengine()
        engine.add_contract(self.CONTRACT_PATH_NEF.replace('.py', '.nef'))
        output, manifest = self.compile_and_save(self.CONTRACT_PATH_NEF.replace('.nef', '.py'))
        ghost_address = hash160(output)

        # when deploying, the contract will mint tokens to the owner
        deploy_event = engine.get_events('Deployed')
        self.assertEqual(1, len(deploy_event))
        self.assertEqual(2, len(deploy_event[0].arguments))

        # add some gas for fees
        add_amount = 10 * 10 ** 8
        engine.add_gas(self.OTHER_ACCOUNT_1, add_amount)

        # check if enough balance
        balance = self.run_smart_contract(engine, self.CONTRACT_PATH_NEF, 'getFeeBalance',
                signer_accounts=[self.OWNER_SCRIPT_HASH],
                expected_result_type=int)
        self.assertEqual(0, balance)

        # mint + getLockedContentViewCount
        token = self.run_smart_contract(engine, self.CONTRACT_PATH_NEF, 'mint', 
                self.OTHER_ACCOUNT_1, self.TOKEN_META, self.LOCK_CONTENT, self.ROYALTIES, None,
                signer_accounts=[self.OTHER_ACCOUNT_1],
                expected_result_type=bytes)
        views = self.run_smart_contract(engine, self.CONTRACT_PATH_NEF, 'getLockedContentViewCount', token,
                expected_result_type=int)

        # should have 0 views
        self.assertEqual(0, views)

        # getLockedContent
        content = self.run_smart_contract(engine, self.CONTRACT_PATH_NEF, 'getLockedContent', token,
                signer_accounts=[self.OTHER_ACCOUNT_1],
                expected_result_type=bytes)
        self.assertEqual(b'lockedContent', content)

        # getLockedContentViewCount should have 1 view
        views = self.run_smart_contract(engine, self.CONTRACT_PATH_NEF, 'getLockedContentViewCount', token,
                expected_result_type=int)
        print("views: " + str(views))
        self.assertEqual(1, views)

        # reset views and test getLockedContentViewCount with 100 views
        views = 0
        for i in range(0, 100):
            views += self.run_smart_contract(engine, self.CONTRACT_PATH_NEF, 'getLockedContentViewCount', token,
                    expected_result_type=int)
        self.assertEqual(100, views)
        self.print_notif(engine.notifications)
