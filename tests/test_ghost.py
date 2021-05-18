from typing import Dict
from boa3_test.tests.boa_test import BoaTest
from boa3_test.tests.test_classes.testengine import TestEngine
from boa3.neo.smart_contract.VoidType import VoidType
from boa3.neo.cryptography import hash160
from boa3.constants import GAS_SCRIPT
from boa3.neo.vm.type.String import String
from boa3.boa3 import Boa3
from boa3.neo import to_script_hash, to_hex_str, from_hex_str
from boa3.builtin.type import UInt160
from boa3_test.tests.test_classes.TestExecutionException import TestExecutionException


class GhostTest(BoaTest):

    CONTRACT_PATH = '/home/merl/source/n3_gm/ghost-n3/ghost.nef'
    OWNER_SCRIPT_HASH = UInt160(to_script_hash(b'NZcuGiwRu1QscpmCyxj5XwQBUf6sk7dJJN'))
    OTHER_ACCOUNT_1 = UInt160(to_script_hash(b'NiNmXL8FjEUEs1nfX9uHFBNaenxDHJtmuB'))
    OTHER_ACCOUNT_2 = bytes(range(20))

    def build_contract(self):
        output, manifest = self.compile_and_save("/home/merl/source/n3_gm/ghost-n3/ghost.py")
        print('address: ' + str(UInt160(hash160(output))))

    def prepare_testengine(self) -> TestEngine:
        self.build_contract()
        root_folder = '/home/merl/source/n3_gm/neo3-boa/boa3'
        engine = TestEngine(root_folder)
        engine.reset_engine()
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
        result = engine.run(self.CONTRACT_PATH, 'symbol', reset_engine=True)
        self.print_notif(engine.notifications)

        assert isinstance(result, str)
        assert result == 'GHOST'

    def test_ghost_decimals(self):
        engine = self.prepare_testengine()
        result = engine.run(self.CONTRACT_PATH, 'decimals', reset_engine=True)
        self.print_notif(engine.notifications)

        assert isinstance(result, int)
        assert result == 0

    def test_ghost_total_supply(self):
        engine = self.prepare_testengine()
        result = engine.run(self.CONTRACT_PATH, 'totalSupply', reset_engine=True)
        self.print_notif(engine.notifications)

        assert isinstance(result, int)
        assert result == 0

    def test_ghost_deploy(self):
        engine = self.prepare_testengine()

        print(1)
        # needs the owner signature
        result = self.run_smart_contract(engine, self.CONTRACT_PATH, 'deploy', expected_result_type=bool)
        self.assertEqual(False, result)

        print(2)
        # should return false if the signature isn't from the owner
        esult = self.run_smart_contract(engine, self.CONTRACT_PATH, 'deploy',
                                        signer_accounts=[self.OTHER_ACCOUNT_1],
                                        expected_result_type=bool)
        self.assertEqual(False, result)

        print(3)
        result = self.run_smart_contract(engine, self.CONTRACT_PATH, 'deploy',
                                         signer_accounts=[self.OWNER_SCRIPT_HASH],
                                         expected_result_type=bool)
        self.assertEqual(True, result)
        print(4)

        # must always return false after first execution
        result = self.run_smart_contract(engine, self.CONTRACT_PATH, 'deploy',
                                         signer_accounts=[self.OWNER_SCRIPT_HASH],
                                         expected_result_type=bool)
        self.assertEqual(False, result)
        self.print_notif(engine.notifications)

    def test_ghost_multi_burn(self):
        engine = self.prepare_testengine()
        engine.add_contract(self.CONTRACT_PATH.replace('.py', '.nef'))

        aux_path = self.get_contract_path('test_native', 'auxiliary_contract.py')

        output, manifest = self.compile_and_save(self.CONTRACT_PATH.replace('.nef', '.py'))
        ghost_address = hash160(output)
        print(to_hex_str(ghost_address))

        output, manifest = self.compile_and_save(aux_path)
        aux_address = hash160(output)
        print(to_hex_str(aux_address))

        add_amount = 10 * 10 ** 8
        # deploying ghost smart contract
        result = self.run_smart_contract(engine, self.CONTRACT_PATH, 'deploy',
                                         signer_accounts=[self.OWNER_SCRIPT_HASH],
                                         expected_result_type=bool)
        self.assertEqual(True, result)
        # when deploying, the contract will mint tokens to the owner
        deploy_event = engine.get_events('Deploy')
        self.assertEqual(1, len(deploy_event))
        self.assertEqual(2, len(deploy_event[0].arguments))

        engine.add_gas(aux_address, add_amount)

        tokenMeta = [
                '{ "name": "GHOST", "description": "A ghost shows up", "image": "{some image URI}", "tokenURI": "{some URI}" }',
                '{ "name": "GHOST2", "description": "A ghost shows up", "image": "{some image URI}", "tokenURI": "{some URI}" }',
                '{ "name": "GHOST3", "description": "A ghost shows up", "image": "{some image URI}", "tokenURI": "{some URI}" }'
            ]

        result = self.run_smart_contract(engine, self.CONTRACT_PATH, 'multiMint', 
                aux_address, tokenMeta, lockedContent, None,
                signer_accounts=[aux_address],
                expected_result_type=list)

        print(result)
        ghost_balance_after = self.run_smart_contract(engine, self.CONTRACT_PATH, 'balanceOf', aux_address)
        self.assertEqual(3, ghost_balance_after)

        ghost_supply_after = self.run_smart_contract(engine, self.CONTRACT_PATH, 'totalSupply')
        self.assertEqual(3, ghost_supply_after)

        burned = self.run_smart_contract(engine, self.CONTRACT_PATH, 'multiBurn', result,
                signer_accounts=[aux_address],
                expected_result_type=list)
        print(burned)
        # self.print_notif(engine.notifications)

        ghost_balance_after = self.run_smart_contract(engine, self.CONTRACT_PATH, 'balanceOf', aux_address)
        self.assertEqual(0, ghost_balance_after)

        ghost_supply_after = self.run_smart_contract(engine, self.CONTRACT_PATH, 'totalSupply')
        self.assertEqual(0, ghost_supply_after)

    def test_ghost_multi_mint(self):
        engine = self.prepare_testengine()
        engine.add_contract(self.CONTRACT_PATH.replace('.py', '.nef'))

        aux_path = self.get_contract_path('test_native', 'auxiliary_contract.py')

        output, manifest = self.compile_and_save(self.CONTRACT_PATH.replace('.nef', '.py'))
        ghost_address = hash160(output)
        print(to_hex_str(ghost_address))

        output, manifest = self.compile_and_save(aux_path)
        aux_address = hash160(output)
        print(to_hex_str(aux_address))

        add_amount = 10 * 10 ** 8
        # deploying ghost smart contract
        result = self.run_smart_contract(engine, self.CONTRACT_PATH, 'deploy',
                                         signer_accounts=[self.OWNER_SCRIPT_HASH],
                                         expected_result_type=bool)
        self.assertEqual(True, result)
        # when deploying, the contract will mint tokens to the owner
        deploy_event = engine.get_events('Deploy')
        self.assertEqual(1, len(deploy_event))
        self.assertEqual(2, len(deploy_event[0].arguments))

        engine.add_gas(aux_address, add_amount)

        tokenMeta = [
                '{ "name": "GHOST", "description": "A ghost shows up", "image": "{some image URI}", "tokenURI": "{some URI}" }',
                '{ "name": "GHOST2", "description": "A ghost shows up", "image": "{some image URI}", "tokenURI": "{some URI}" }',
                '{ "name": "GHOST3", "description": "A ghost shows up", "image": "{some image URI}", "tokenURI": "{some URI}" }'
            ]
        lockedContent = [
                '123',
                '456',
                '789',
            ]

        result = self.run_smart_contract(engine, self.CONTRACT_PATH, 'multiMint', 
                aux_address, tokenMeta, lockedContent, None,
                signer_accounts=[aux_address],
                expected_result_type=list)

        print(result)
        # self.print_notif(engine.notifications)

        # gas_ghost_after = self.run_smart_contract(engine, GAS_SCRIPT, 'balanceOf', ghost_address)
        # self.assertEqual(3, gas_ghost_after)

        # gas_aux_after = self.run_smart_contract(engine, GAS_SCRIPT, 'balanceOf', aux_address)
        # self.assertEqual(3, gas_aux_after)

        ghost_balance_after = self.run_smart_contract(engine, self.CONTRACT_PATH, 'balanceOf', aux_address)
        self.assertEqual(3, ghost_balance_after)

        ghost_supply_after = self.run_smart_contract(engine, self.CONTRACT_PATH, 'totalSupply')
        self.assertEqual(3, ghost_supply_after)

    def test_ghost_mint(self):
        engine = self.prepare_testengine()
        engine.add_contract(self.CONTRACT_PATH.replace('.py', '.nef'))

        aux_path = self.get_contract_path('test_native', 'auxiliary_contract.py')

        output, manifest = self.compile_and_save(self.CONTRACT_PATH.replace('.nef', '.py'))
        ghost_address = hash160(output)
        print(to_hex_str(ghost_address))

        output, manifest = self.compile_and_save(aux_path)
        aux_address = hash160(output)
        print(to_hex_str(aux_address))

        add_amount = 10 * 10 ** 8
        # deploying ghost smart contract
        result = self.run_smart_contract(engine, self.CONTRACT_PATH, 'deploy',
                                         signer_accounts=[self.OWNER_SCRIPT_HASH],
                                         expected_result_type=bool)
        self.assertEqual(True, result)
        # when deploying, the contract will mint tokens to the owner
        deploy_event = engine.get_events('Deploy')
        self.assertEqual(1, len(deploy_event))
        self.assertEqual(2, len(deploy_event[0].arguments))

        engine.add_gas(aux_address, add_amount)
        tokenMeta = {
           "name": "GHOST",
           "description": "A ghost shows up",
           "image": "{some image URI}",
           "tokenURI": "{some URI}"
            }

        token = self.run_smart_contract(engine, self.CONTRACT_PATH, 'mint', 
                aux_address, tokenMeta, "lockedContent", None,
                signer_accounts=[aux_address],
                expected_result_type=bytes)

        properties = self.run_smart_contract(engine, self.CONTRACT_PATH, 'properties', token)
        self.print_notif(engine.notifications)
        print("props: " + str(properties))

        ghost_amount_after = self.run_smart_contract(engine, GAS_SCRIPT, 'balanceOf', ghost_address)
        gas_aux_after = self.run_smart_contract(engine, GAS_SCRIPT, 'balanceOf', aux_address)
        print("ghost gas amount: " + str(ghost_amount_after))
        print("aux gas amount: " + str(gas_aux_after))
        ghost_balance_after = self.run_smart_contract(engine, self.CONTRACT_PATH, 'balanceOf', aux_address)
        print("balance nft: " + str(ghost_balance_after))
        ghost_supply_after = self.run_smart_contract(engine, self.CONTRACT_PATH, 'totalSupply')
        print("supply nft: " + str(ghost_supply_after))
        self.assertEqual(1, ghost_supply_after)

    def test_ghost_burn(self):
        engine = self.prepare_testengine()
        engine.add_contract(self.CONTRACT_PATH.replace('.py', '.nef'))

        aux_path = self.get_contract_path('test_native', 'auxiliary_contract.py')

        output, manifest = self.compile_and_save(self.CONTRACT_PATH.replace('.nef', '.py'))
        ghost_address = hash160(output)
        print(to_hex_str(ghost_address))

        output, manifest = self.compile_and_save(aux_path)
        aux_address = hash160(output)
        print(to_hex_str(aux_address))

        add_amount = 10 * 10 ** 8
        # deploying ghost smart contract
        result = self.run_smart_contract(engine, self.CONTRACT_PATH, 'deploy',
                                         signer_accounts=[self.OWNER_SCRIPT_HASH],
                                         expected_result_type=bool)
        self.assertEqual(True, result)
        # when deploying, the contract will mint tokens to the owner
        deploy_event = engine.get_events('Deploy')
        self.assertEqual(1, len(deploy_event))
        self.assertEqual(2, len(deploy_event[0].arguments))

        engine.add_gas(aux_address, add_amount)
        tokenMeta = {
           "name": "GHOST",
           "description": "A ghost shows up",
           "image": "{some image URI}",
           "tokenURI": "{some URI}"
            }

        token = self.run_smart_contract(engine, self.CONTRACT_PATH, 'mint', 
                aux_address, tokenMeta, None,
                signer_accounts=[aux_address],
                expected_result_type=bytes)

        properties = self.run_smart_contract(engine, self.CONTRACT_PATH, 'burn', token,
                signer_accounts=[aux_address],
                expected_result_type=bool)
        
        self.print_notif(engine.notifications)

        ghost_balance_after = self.run_smart_contract(engine, self.CONTRACT_PATH, 'balanceOf', aux_address)
        self.assertEqual(0, ghost_balance_after)
        ghost_supply_after = self.run_smart_contract(engine, self.CONTRACT_PATH, 'totalSupply')
        self.assertEqual(0, ghost_supply_after)

    def test_ghost_onNEP17Payment(self):
        engine = self.prepare_testengine()
        engine.add_contract(self.CONTRACT_PATH.replace('.py', '.nef'))

        aux_path = self.get_contract_path('test_native', 'auxiliary_contract.py')

        output, manifest = self.compile_and_save(self.CONTRACT_PATH.replace('.nef', '.py'))
        ghost_address = hash160(output)
        print(to_hex_str(ghost_address))

        output, manifest = self.compile_and_save(aux_path)
        aux_address = hash160(output)
        print(to_hex_str(aux_address))

        add_amount = 10 * 10 ** 8
        # deploying ghost smart contract
        result = self.run_smart_contract(engine, self.CONTRACT_PATH, 'deploy',
                                         signer_accounts=[self.OWNER_SCRIPT_HASH],
                                         expected_result_type=bool)
        self.assertEqual(True, result)
        # when deploying, the contract will mint tokens to the owner
        deploy_event = engine.get_events('Deploy')
        self.assertEqual(1, len(deploy_event))
        self.assertEqual(2, len(deploy_event[0].arguments))

        engine.add_gas(aux_address, add_amount)
        ## engine.add_gas(ghost_address, add_amount)

        # the smart contract will abort if some address other than GAS calls the onPayment method
        with self.assertRaises(TestExecutionException, msg=self.ABORTED_CONTRACT_MSG):
            self.run_smart_contract(engine, self.CONTRACT_PATH, 'onNEP17Payment', aux_address, add_amount, None,
                                    signer_accounts=[aux_address])

    def test_ghost_mint_fee(self):
        engine = self.prepare_testengine()
        engine.add_contract(self.CONTRACT_PATH.replace('.py', '.nef'))

        output, manifest = self.compile_and_save(self.CONTRACT_PATH.replace('.nef', '.py'))
        ghost_address = hash160(output)

        add_amount = 10 * 10 ** 8
        # deploying ghost smart contract
        result = self.run_smart_contract(engine, self.CONTRACT_PATH, 'deploy',
                                         signer_accounts=[self.OWNER_SCRIPT_HASH],
                                         expected_result_type=bool)
        self.assertEqual(True, result)
        # when deploying, the contract will mint tokens to the owner
        deploy_event = engine.get_events('Deploy')
        self.assertEqual(1, len(deploy_event))
        self.assertEqual(2, len(deploy_event[0].arguments))

        engine.add_gas(self.OTHER_ACCOUNT_1, add_amount/2)
        engine.add_gas(self.OWNER_SCRIPT_HASH, add_amount/2)

        fee = self.run_smart_contract(engine, self.CONTRACT_PATH, 'setMintFee', 1000,
                signer_accounts=[self.OWNER_SCRIPT_HASH],
                expected_result_type=int)

        self.assertEqual(1000, fee)
        fee2 = self.run_smart_contract(engine, self.CONTRACT_PATH, 'getMintFee', expected_result_type=int)
        self.assertEqual(fee2, fee)

        # fails because account not whitelisted
        with self.assertRaises(TestExecutionException, msg=self.ASSERT_RESULTED_FALSE_MSG):
            self.run_smart_contract(engine, self.CONTRACT_PATH, 'setMintFee', 1,
                                    signer_accounts=[self.OTHER_ACCOUNT_1])

        fee2 = self.run_smart_contract(engine, self.CONTRACT_PATH, 'getMintFee', expected_result_type=int)
        self.assertEqual(fee2, fee)

    def test_ghost_fee_balance(self):
        engine = self.prepare_testengine()
        engine.add_contract(self.CONTRACT_PATH.replace('.py', '.nef'))

        output, manifest = self.compile_and_save(self.CONTRACT_PATH.replace('.nef', '.py'))
        ghost_address = hash160(output)

        add_amount = 10 * 10 ** 8
        # deploying ghost smart contract
        result = self.run_smart_contract(engine, self.CONTRACT_PATH, 'deploy',
                                         signer_accounts=[self.OWNER_SCRIPT_HASH],
                                         expected_result_type=bool)
        self.assertEqual(True, result)
        # when deploying, the contract will mint tokens to the owner
        deploy_event = engine.get_events('Deploy')
        self.assertEqual(1, len(deploy_event))
        self.assertEqual(2, len(deploy_event[0].arguments))

        engine.add_gas(self.OTHER_ACCOUNT_1, 100000000)
        #engine.add_gas(self.OWNER_SCRIPT_HASH, 2000000)

        balance = self.run_smart_contract(engine, self.CONTRACT_PATH, 'getFeeBalance',
                signer_accounts=[self.OWNER_SCRIPT_HASH],
                expected_result_type=int)

        self.assertEqual(0, balance)

        tokenMeta = {
           "name": "GHOST",
           "description": "A ghost shows up",
           "image": "{some image URI}",
           "tokenURI": "{some URI}"
            }

        token = self.run_smart_contract(engine, self.CONTRACT_PATH, 'mint', 
                self.OTHER_ACCOUNT_1, tokenMeta, "lockedContent", None,
                signer_accounts=[self.OTHER_ACCOUNT_1],
                expected_result_type=bytes)

        ghost_balance_after = self.run_smart_contract(engine, GAS_SCRIPT, 'balanceOf', ghost_address)

        self.assertEqual(10000000, ghost_balance_after)

        # set mint fee to 200000
        fee = self.run_smart_contract(engine, self.CONTRACT_PATH, 'setMintFee', 200000,
                signer_accounts=[self.OWNER_SCRIPT_HASH],
                expected_result_type=int)

        tokenMeta = {
           "name": "GHOST",
           "description": "A ghost shows up",
           "image": "{some image URI}",
           "tokenURI": "{some URI}"
            }

        token = self.run_smart_contract(engine, self.CONTRACT_PATH, 'mint', 
                self.OTHER_ACCOUNT_1, tokenMeta, "lockedContent", None,
                signer_accounts=[self.OTHER_ACCOUNT_1],
                expected_result_type=bytes)

        ghost_balance_after = self.run_smart_contract(engine, self.CONTRACT_PATH, 'getFeeBalance',
                signer_accounts=[self.OWNER_SCRIPT_HASH],
                expected_result_type=int)

        self.assertEqual(10000000 + 200000, ghost_balance_after)

        # withdraw fee
        success = self.run_smart_contract(engine, self.CONTRACT_PATH, 'withdrawFee', self.OWNER_SCRIPT_HASH,
                signer_accounts=[self.OWNER_SCRIPT_HASH],
                expected_result_type=int)

        self.assertEqual(True, success)

        ghost_balance_after = self.run_smart_contract(engine, GAS_SCRIPT, 'balanceOf', ghost_address)
        self.assertEqual(0, ghost_balance_after)

        owner_balance = self.run_smart_contract(engine, GAS_SCRIPT, 'balanceOf', self.OWNER_SCRIPT_HASH)
        self.assertEqual(10000000 + 200000, owner_balance)
        self.print_notif(engine.notifications)

        
    def test_ghost_locked_content(self):
        engine = self.prepare_testengine()
        engine.add_contract(self.CONTRACT_PATH.replace('.py', '.nef'))

        output, manifest = self.compile_and_save(self.CONTRACT_PATH.replace('.nef', '.py'))
        ghost_address = hash160(output)

        add_amount = 10 * 10 ** 8
        # deploying ghost smart contract
        result = self.run_smart_contract(engine, self.CONTRACT_PATH, 'deploy',
                                         signer_accounts=[self.OWNER_SCRIPT_HASH],
                                         expected_result_type=bool)
        self.assertEqual(True, result)
        # when deploying, the contract will mint tokens to the owner
        deploy_event = engine.get_events('Deploy')
        self.assertEqual(1, len(deploy_event))
        self.assertEqual(2, len(deploy_event[0].arguments))

        engine.add_gas(self.OTHER_ACCOUNT_1, 100000000)
        #engine.add_gas(self.OWNER_SCRIPT_HASH, 2000000)

        balance = self.run_smart_contract(engine, self.CONTRACT_PATH, 'getFeeBalance',
                signer_accounts=[self.OWNER_SCRIPT_HASH],
                expected_result_type=int)

        self.assertEqual(0, balance)

        tokenMeta = {
           "name": "GHOST",
           "description": "A ghost shows up",
           "image": "{some image URI}",
           "tokenURI": "{some URI}"
            }

        lockedContent = b'superSecureLockedContent'
        token = self.run_smart_contract(engine, self.CONTRACT_PATH, 'mint', 
                self.OTHER_ACCOUNT_1, tokenMeta, lockedContent, None,
                signer_accounts=[self.OTHER_ACCOUNT_1],
                expected_result_type=bytes)

        views = self.run_smart_contract(engine, self.CONTRACT_PATH, 'getLockedContentViewCount', token,
                expected_result_type=int)
        self.assertEqual(0, views)

        # retrieve locked content
        content = self.run_smart_contract(engine, self.CONTRACT_PATH, 'getLockedContent', token,
                signer_accounts=[self.OTHER_ACCOUNT_1],
                expected_result_type=bytes)
        self.assertEqual(lockedContent, content)
        
        views = self.run_smart_contract(engine, self.CONTRACT_PATH, 'getLockedContentViewCount', token,
                expected_result_type=int)
        print("views: " + str(views))
        self.assertEqual(1, views)

        # reset views
        views = 0
        for i in range(0, 100):
            views += self.run_smart_contract(engine, self.CONTRACT_PATH, 'getLockedContentViewCount', token,
                    expected_result_type=int)
        self.assertEqual(100, views)

        self.print_notif(engine.notifications)
        








        










        






        
        







        
