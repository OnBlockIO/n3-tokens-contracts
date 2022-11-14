from pathlib import Path
from boa3.neo import to_script_hash
from boa3.neo.vm.type.String import String
from boa3.neo.smart_contract.VoidType import VoidType
from boa3_test.tests.boa_test import BoaTest
from boa3_test.tests.test_classes.TestExecutionException import TestExecutionException
from boa3_test.tests.test_classes.testengine import TestEngine
from boa3.builtin.type import UInt160
from boa3.builtin.interop.iterator import Iterator
from boa3_test.tests.test_classes.TestExecutionException import TestExecutionException
from boa3.neo.core.types.InteropInterface import InteropInterface


class GhostTest(BoaTest):
    p = Path(__file__)
    GHOST_ROOT = str(p.parents[1])
    PRJ_ROOT = str(p.parents[2])

    CONTRACT_PATH_JSON = GHOST_ROOT + '/contracts/NEP17/GhostMarketToken.manifest.json'
    CONTRACT_PATH_NEF = GHOST_ROOT + '/contracts/NEP17/GhostMarketToken.nef'
    CONTRACT_PATH_PY = GHOST_ROOT + '/contracts/NEP17/GhostMarketToken.py'
    TEST_ENGINE_PATH = '%s/neo-devpack-dotnet/src/Neo.TestEngine/bin/Debug/net6.0' % GHOST_ROOT
    CHECKPOINT_PATH = '%s/checkpoints/contracts-deployed.neoxp-checkpoint'
    BOA_PATH = PRJ_ROOT + '/neo3-boa/boa3'
    DEPLOYER_ACCOUNT = UInt160(b'\x9c\xa5/\x04"{\xf6Z\xe2\xe5\xd1\xffe\x03\xd1\x9dd\xc2\x9cF')
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

    def prepare_testengine(self, preprocess=False) -> TestEngine:
        engine = TestEngine(self.TEST_ENGINE_PATH)
        engine.reset_engine()
        return engine

    def test_gm_compile(self):
        output, manifest = self.compile_and_save(self.CONTRACT_PATH_PY)

        self.assertIn('supportedstandards', manifest)
        self.assertIsInstance(manifest['supportedstandards'], list)

    def test_gm_symbol(self):
        engine = self.prepare_testengine()
        result = self.run_smart_contract(engine, self.CONTRACT_PATH_NEF, 'symbol', expected_result_type=str)
        self.assertEqual('GM', result)

    def test_gm_decimals(self):
        engine = self.prepare_testengine()
        result = self.run_smart_contract(engine, self.CONTRACT_PATH_NEF, 'decimals')
        self.assertEqual(8, result)

    def test_gm_total_supply(self):
        total_supply = 100_000_000 * 10 ** 8

        engine = self.prepare_testengine()
        result = self.run_smart_contract(engine, self.CONTRACT_PATH_NEF, 'totalSupply')
        self.assertEqual(total_supply, result)

    def test_gm_allowance(self):
        approval = 1_000
        transferred_amount = 500
        
        engine = self.prepare_testengine()

        # should have allowance of 0 by default
        result = self.run_smart_contract(engine, self.CONTRACT_PATH_NEF, 'allowance',
                                        self.DEPLOYER_ACCOUNT, self.OTHER_ACCOUNT_1,
                                        expected_result_type=int)
        self.assertEqual(0, result)

        # should fail when the approve is less than 0
        with self.assertRaises(TestExecutionException, msg=self.ASSERT_RESULTED_FALSE_MSG):
            self.run_smart_contract(engine, self.CONTRACT_PATH_NEF, 'approve',
                                    self.OWNER_SCRIPT_HASH, self.OTHER_ACCOUNT_1, -10,
                                    signer_accounts=[self.OWNER_SCRIPT_HASH])

        # set an approval for 1000
        result = self.run_smart_contract(engine, self.CONTRACT_PATH_NEF, 'approve',
                                        self.OWNER_SCRIPT_HASH, self.OTHER_ACCOUNT_1, approval,
                                        signer_accounts=[self.OWNER_SCRIPT_HASH])
        self.assertEqual(True, result)
        transfer_events = engine.get_events('Approval')
        self.assertEqual(1, len(transfer_events))
        self.assertEqual(3, len(transfer_events[0].arguments))

        owner, spender, amount = transfer_events[0].arguments
        if isinstance(owner, str):
            owner = String(owner).to_bytes()
        if isinstance(spender, str):
            spender = String(spender).to_bytes()
        self.assertEqual(self.OWNER_SCRIPT_HASH, owner)
        self.assertEqual(self.OTHER_ACCOUNT_1, spender)
        self.assertEqual(approval, amount)

        # should now have allowance of 1000
        result = self.run_smart_contract(engine, self.CONTRACT_PATH_NEF, 'allowance',
                                        self.OWNER_SCRIPT_HASH, self.OTHER_ACCOUNT_1,
                                        expected_result_type=int)
        self.assertEqual(approval, result)

        # transfer from deployer to owner
        result = self.run_smart_contract(engine, self.CONTRACT_PATH_NEF, 'transfer',
                                         self.DEPLOYER_ACCOUNT, self.OWNER_SCRIPT_HASH, transferred_amount, None,
                                         signer_accounts=[self.OWNER_SCRIPT_HASH],
                                         expected_result_type=bool)
        self.assertEqual(True, result)

        # initiate a transfer of 500
        result = self.run_smart_contract(engine, self.CONTRACT_PATH_NEF, 'transferFrom',
                                        self.OTHER_ACCOUNT_1, self.OWNER_SCRIPT_HASH, self.OTHER_ACCOUNT_2, transferred_amount, None,
                                        signer_accounts=[self.OTHER_ACCOUNT_1],
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
        self.assertEqual(self.OTHER_ACCOUNT_2, receiver)
        self.assertEqual(transferred_amount, amount)

        # should now have allowance of 500
        result = self.run_smart_contract(engine, self.CONTRACT_PATH_NEF, 'allowance',
                                        self.OWNER_SCRIPT_HASH, self.OTHER_ACCOUNT_1,
                                        expected_result_type=int)
        self.assertEqual(amount, result)

    def test_gm_total_balance_of(self):
        total_supply = 100_000_000 * 10 ** 8

        engine = self.prepare_testengine()

        result = self.run_smart_contract(engine, self.CONTRACT_PATH_NEF, 'balanceOf', self.DEPLOYER_ACCOUNT,
                                                         signer_accounts=[self.OWNER_SCRIPT_HASH])
        self.print_notif(engine.notifications)
        self.assertEqual(total_supply, result)

        # should fail when the script length is not 20
        with self.assertRaises(TestExecutionException, msg=self.ASSERT_RESULTED_FALSE_MSG):
            self.run_smart_contract(engine, self.CONTRACT_PATH_NEF, 'balanceOf', bytes(10))
        with self.assertRaises(TestExecutionException, msg=self.ASSERT_RESULTED_FALSE_MSG):
            self.run_smart_contract(engine, self.CONTRACT_PATH_NEF, 'balanceOf', bytes(30))

        self.print_notif(engine.notifications)

    def test_gm_total_transfer(self):
        transferred_amount = 10 * 10 ** 8  # 10 tokens

        engine = self.prepare_testengine()

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
        balance_before = self.run_smart_contract(engine, self.CONTRACT_PATH_NEF, 'balanceOf', self.DEPLOYER_ACCOUNT)
        result = self.run_smart_contract(engine, self.CONTRACT_PATH_NEF, 'transfer',
                                         self.DEPLOYER_ACCOUNT, self.DEPLOYER_ACCOUNT, transferred_amount, None,
                                         signer_accounts=[self.DEPLOYER_ACCOUNT],
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
        self.assertEqual(self.DEPLOYER_ACCOUNT, sender)
        self.assertEqual(self.DEPLOYER_ACCOUNT, receiver)
        self.assertEqual(transferred_amount, amount)

        # transferring to yourself doesn't change the balance
        balance_after = self.run_smart_contract(engine, self.CONTRACT_PATH_NEF, 'balanceOf', self.DEPLOYER_ACCOUNT)
        self.assertEqual(balance_before, balance_after)

        # does fire the transfer event
        balance_sender_before = self.run_smart_contract(engine, self.CONTRACT_PATH_NEF, 'balanceOf', self.DEPLOYER_ACCOUNT)
        balance_receiver_before = self.run_smart_contract(engine, self.CONTRACT_PATH_NEF, 'balanceOf', self.OTHER_ACCOUNT_1)
        result = self.run_smart_contract(engine, self.CONTRACT_PATH_NEF, 'transfer',
                                         self.DEPLOYER_ACCOUNT, self.OTHER_ACCOUNT_1, transferred_amount, None,
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
        self.assertEqual(self.DEPLOYER_ACCOUNT, sender)
        self.assertEqual(self.OTHER_ACCOUNT_1, receiver)
        self.assertEqual(transferred_amount, amount)

        # transferring to someone other than yourself does change the balance
        balance_sender_after = self.run_smart_contract(engine, self.CONTRACT_PATH_NEF, 'balanceOf', self.DEPLOYER_ACCOUNT)
        balance_receiver_after = self.run_smart_contract(engine, self.CONTRACT_PATH_NEF, 'balanceOf', self.OTHER_ACCOUNT_1)
        self.assertEqual(balance_sender_before - transferred_amount, balance_sender_after)
        self.assertEqual(balance_receiver_before + transferred_amount, balance_receiver_after)