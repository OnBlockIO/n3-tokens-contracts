from boa3 import constants
from pathlib import Path
from boa3.boa3 import Boa3
from boa3.neo import to_script_hash
from boa3.neo.cryptography import hash160
from boa3.neo.vm.type.String import String
from boa3.neo.smart_contract.VoidType import VoidType
from boa3_test.tests.boa_test import BoaTest
from boa3_test.tests.test_classes.TestExecutionException import TestExecutionException
from boa3_test.tests.test_classes.testengine import TestEngine
from boa3.builtin.type import UInt160
from boa3.builtin.interop.iterator import Iterator
from boa3_test.tests.test_classes.TestExecutionException import TestExecutionException
from boa3.neo.core.types.InteropInterface import InteropInterface

CONTRACT_BUILT = False

class TestNEP17(BoaTest):
    p = Path(__file__)
    GHOST_ROOT = str(p.parents[1])
    PRJ_ROOT = str(p.parents[2])

    CONTRACT_PATH_JSON = GHOST_ROOT+ '/contracts/NEP17/NEP17.manifest.json'
    CONTRACT_PATH_NEF = GHOST_ROOT + '/contracts/NEP17/NEP17.nef'
    CONTRACT_PATH_PY = GHOST_ROOT + '/contracts/NEP17/NEP17.py'
    TEST_ENGINE_PATH = '/home/merl/source/n3_gm/neo-devpack-dotnet/src/Neo.TestEngine/bin/Debug/net5.0/'
    BOA_PATH = PRJ_ROOT + '/neo3-boa/boa3'
    OWNER_SCRIPT_HASH = UInt160(to_script_hash(b'NZcuGiwRu1QscpmCyxj5XwQBUf6sk7dJJN'))
    OTHER_ACCOUNT_1 = UInt160(to_script_hash(b'NiNmXL8FjEUEs1nfX9uHFBNaenxDHJtmuB'))
    OTHER_ACCOUNT_2 = bytes(range(20))

    def print_notif(self, notifications):
        print('\n=========================== NOTIFICATIONS START ===========================\n')
        for notif in notifications:
            print(f"{str(notif.name)}: {str(notif.arguments)}")
        print('\n=========================== NOTIFICATIONS END ===========================\n')

    def deploy_contract(self, engine):
        engine.add_contract(self.CONTRACT_PATH_NEF)
        result = self.run_smart_contract(engine, self.CONTRACT_PATH_NEF, '_deploy', None, False,
                                         signer_accounts=[self.OWNER_SCRIPT_HASH])
        self.assertEqual(VoidType, result)

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
        CONTRACT_BUILT = True;

    def prepare_testengine(self, preprocess=False) -> TestEngine:
        if not CONTRACT_BUILT:
            self.build_contract(preprocess)
        engine = TestEngine(self.TEST_ENGINE_PATH)
        engine.reset_engine()
        self.deploy_contract(engine)
        return engine

    def test_nep17_compile(self):
        output, manifest = self.compile_and_save(self.CONTRACT_PATH_PY)

        self.assertIn('supportedstandards', manifest)
        self.assertIsInstance(manifest['supportedstandards'], list)
        # self.assertGreater(len(manifest['supportedstandards']), 0)
        # self.assertIn('NEP-17', manifest['supportedstandards'])

    def test_nep17_deploy(self):
        # prepare_testengine already deploys the contract and verifies it's successfully deployed
        engine = self.prepare_testengine()

        # must always return false after first execution
        with self.assertRaises(TestExecutionException, msg=self.ABORTED_CONTRACT_MSG):
            result = self.run_smart_contract(engine, self.CONTRACT_PATH_NEF, '_deploy', None, False,
                                             signer_accounts=[self.OWNER_SCRIPT_HASH],
                                         expected_result_type=bool)
        self.print_notif(engine.notifications)

    def test_nep17_symbol(self):
        engine = self.prepare_testengine()
        result = self.run_smart_contract(engine, self.CONTRACT_PATH_NEF, 'symbol', expected_result_type=str)
        self.assertEqual('GM', result)

    def test_nep17_decimals(self):
        engine = self.prepare_testengine()
        result = self.run_smart_contract(engine, self.CONTRACT_PATH_NEF, 'decimals')
        self.assertEqual(8, result)

    def test_nep17_total_supply(self):
        total_supply = 100_000_000 * 10 ** 8

        engine = self.prepare_testengine()
        result = self.run_smart_contract(engine, self.CONTRACT_PATH_NEF, 'totalSupply')
        self.assertEqual(total_supply, result)

    def test_nep17_total_balance_of(self):
        total_supply = 100_000_000 * 10 ** 8

        engine = self.prepare_testengine()

        result = self.run_smart_contract(engine, self.CONTRACT_PATH_NEF, 'balanceOf', self.OWNER_SCRIPT_HASH)
        self.print_notif(engine.notifications)
        self.assertEqual(total_supply, result)

        # should fail when the script length is not 20
        with self.assertRaises(TestExecutionException, msg=self.ASSERT_RESULTED_FALSE_MSG):
            self.run_smart_contract(engine, self.CONTRACT_PATH_NEF, 'balanceOf', bytes(10))
        with self.assertRaises(TestExecutionException, msg=self.ASSERT_RESULTED_FALSE_MSG):
            self.run_smart_contract(engine, self.CONTRACT_PATH_NEF, 'balanceOf', bytes(30))

        self.print_notif(engine.notifications)

    def test_nep17_total_transfer(self):
        transferred_amount = 10 * 10 ** 8  # 10 tokens

        engine = self.prepare_testengine()

        # should fail before running deploy
        result = self.run_smart_contract(engine, self.CONTRACT_PATH_NEF, 'transfer',
                                         self.OWNER_SCRIPT_HASH, self.OTHER_ACCOUNT_1, transferred_amount, None,
                                         expected_result_type=bool)
        self.assertEqual(False, result)
        # when deploying, the contract will mint tokens to the owner
        transfer_events = engine.get_events('Transfer')
        self.assertEqual(1, len(transfer_events))
        self.assertEqual(3, len(transfer_events[0].arguments))

        sender, receiver, amount = transfer_events[0].arguments
        if isinstance(sender, str):
            sender = String(sender).to_bytes()
        if isinstance(receiver, str):
            receiver = String(receiver).to_bytes()
        self.assertEqual(None, sender)
        self.assertEqual(self.OWNER_SCRIPT_HASH, receiver)
        self.assertEqual(100_000_000 * 100_000_000, amount)

        # should fail if the sender doesn't sign
        result = self.run_smart_contract(engine, self.CONTRACT_PATH_NEF, 'transfer',
                                         self.OWNER_SCRIPT_HASH, self.OTHER_ACCOUNT_1, transferred_amount, None,
                                         expected_result_type=bool)
        self.assertEqual(False, result)

        # should fail if the sender doesn't have enough balance
        result = self.run_smart_contract(engine, self.CONTRACT_PATH_NEF, 'transfer',
                                         self.OTHER_ACCOUNT_1, self.OWNER_SCRIPT_HASH, transferred_amount, None,
                                         signer_accounts=[self.OTHER_ACCOUNT_1],
                                         expected_result_type=bool)
        self.assertEqual(False, result)

        # should fail when any of the scripts' length is not 20
        with self.assertRaises(TestExecutionException, msg=self.ASSERT_RESULTED_FALSE_MSG):
            self.run_smart_contract(engine, self.CONTRACT_PATH_NEF, 'transfer',
                                    self.OWNER_SCRIPT_HASH, bytes(10), transferred_amount, "")
        with self.assertRaises(TestExecutionException, msg=self.ASSERT_RESULTED_FALSE_MSG):
            self.run_smart_contract(engine, self.CONTRACT_PATH_NEF, 'transfer',
                                    bytes(10), self.OTHER_ACCOUNT_1, transferred_amount, "")

        # should fail when the amount is less than 0
        with self.assertRaises(TestExecutionException, msg=self.ASSERT_RESULTED_FALSE_MSG):
            self.run_smart_contract(engine, self.CONTRACT_PATH_NEF, 'transfer',
                                    self.OTHER_ACCOUNT_1, self.OWNER_SCRIPT_HASH, -10, None)

        # fire the transfer event when transferring to yourself
        balance_before = self.run_smart_contract(engine, self.CONTRACT_PATH_NEF, 'balanceOf', self.OWNER_SCRIPT_HASH)
        result = self.run_smart_contract(engine, self.CONTRACT_PATH_NEF, 'transfer',
                                         self.OWNER_SCRIPT_HASH, self.OWNER_SCRIPT_HASH, transferred_amount, None,
                                         signer_accounts=[self.OWNER_SCRIPT_HASH],
                                         expected_result_type=bool)
        self.assertEqual(True, result)
        transfer_events = engine.get_events('Transfer')
        self.assertEqual(2, len(transfer_events))
        self.assertEqual(3, len(transfer_events[1].arguments))

        sender, receiver, amount = transfer_events[1].arguments
        if isinstance(sender, str):
            sender = String(sender).to_bytes()
        if isinstance(receiver, str):
            receiver = String(receiver).to_bytes()
        self.assertEqual(self.OWNER_SCRIPT_HASH, sender)
        self.assertEqual(self.OWNER_SCRIPT_HASH, receiver)
        self.assertEqual(transferred_amount, amount)

        # transferring to yourself doesn't change the balance
        balance_after = self.run_smart_contract(engine, self.CONTRACT_PATH_NEF, 'balanceOf', self.OWNER_SCRIPT_HASH)
        self.assertEqual(balance_before, balance_after)

        # does fire the transfer event
        balance_sender_before = self.run_smart_contract(engine, self.CONTRACT_PATH_NEF, 'balanceOf', self.OWNER_SCRIPT_HASH)
        balance_receiver_before = self.run_smart_contract(engine, self.CONTRACT_PATH_NEF, 'balanceOf', self.OTHER_ACCOUNT_1)
        result = self.run_smart_contract(engine, self.CONTRACT_PATH_NEF, 'transfer',
                                         self.OWNER_SCRIPT_HASH, self.OTHER_ACCOUNT_1, transferred_amount, None,
                                         signer_accounts=[self.OWNER_SCRIPT_HASH],
                                         expected_result_type=bool)
        self.assertEqual(True, result)
        transfer_events = engine.get_events('Transfer')
        self.assertEqual(3, len(transfer_events))
        self.assertEqual(3, len(transfer_events[2].arguments))

        sender, receiver, amount = transfer_events[2].arguments
        if isinstance(sender, str):
            sender = String(sender).to_bytes()
        if isinstance(receiver, str):
            receiver = String(receiver).to_bytes()
        self.assertEqual(self.OWNER_SCRIPT_HASH, sender)
        self.assertEqual(self.OTHER_ACCOUNT_1, receiver)
        self.assertEqual(transferred_amount, amount)

        # transferring to someone other than yourself does change the balance
        balance_sender_after = self.run_smart_contract(engine, self.CONTRACT_PATH_NEF, 'balanceOf', self.OWNER_SCRIPT_HASH)
        balance_receiver_after = self.run_smart_contract(engine, self.CONTRACT_PATH_NEF, 'balanceOf', self.OTHER_ACCOUNT_1)
        self.assertEqual(balance_sender_before - transferred_amount, balance_sender_after)
        self.assertEqual(balance_receiver_before + transferred_amount, balance_receiver_after)

    def test_nep17_onPayment(self):
        transferred_amount = 10 * 10 ** 8  # 10 tokens

        engine = self.prepare_testengine()

        output, manifest = self.compile_and_save(self.CONTRACT_PATH_PY)
        nep17_address = hash160(output)

        aux_path = self.get_contract_path('test_native', 'auxiliary_contract.py')
        output, manifest = self.compile_and_save(aux_path)
        aux_address = hash160(output)

        transfer_events = engine.get_events('Transfer')
        self.assertEqual(1, len(transfer_events))
        transfer_event = transfer_events[0]
        self.assertEqual(3, len(transfer_event.arguments))

        sender, receiver, amount = transfer_event.arguments
        if isinstance(sender, str):
            sender = String(sender).to_bytes()
        if isinstance(receiver, str):
            receiver = String(receiver).to_bytes()
        self.assertEqual(None, sender)
        self.assertEqual(self.OWNER_SCRIPT_HASH, receiver)
        self.assertEqual(100_000_000 * 100_000_000, amount)

        engine.add_neo(aux_address, transferred_amount)
        engine.add_gas(aux_address, transferred_amount)

        with self.assertRaises(TestExecutionException, msg=self.ABORTED_CONTRACT_MSG):
            result = self.run_smart_contract(engine, aux_path, 'calling_transfer', constants.NEO_SCRIPT,
                                         aux_address, nep17_address, transferred_amount, None,
                                         signer_accounts=[aux_address],
                                         expected_result_type=bool)

        with self.assertRaises(TestExecutionException, msg=self.ABORTED_CONTRACT_MSG):
            result = self.run_smart_contract(engine, aux_path, 'calling_transfer', constants.GAS_SCRIPT,
                                         aux_address, nep17_address, transferred_amount, None,
                                         signer_accounts=[aux_address],
                                         expected_result_type=bool)

    def test_nep17_verify(self):
        engine = TestEngine(self.TEST_ENGINE_PATH)
        self.deploy_contract(engine)

        # should fail without signature
        result = self.run_smart_contract(engine, self.CONTRACT_PATH_NEF, 'verify',
                                         expected_result_type=bool)
        self.assertEqual(False, result)

        # should fail if not signed by the owner
        result = self.run_smart_contract(engine, self.CONTRACT_PATH_NEF, 'verify',
                                         signer_accounts=[self.OTHER_ACCOUNT_1],
                                         expected_result_type=bool)
        self.assertEqual(False, result)

        result = self.run_smart_contract(engine, self.CONTRACT_PATH_NEF, 'verify',
                                         signer_accounts=[self.OWNER_SCRIPT_HASH],
                                         expected_result_type=bool)
        self.assertEqual(True, result)
