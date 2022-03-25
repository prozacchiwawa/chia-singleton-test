import argparse
import asyncio
import binascii
from blspy import AugSchemeMPL, G1Element, G2Element, PrivateKey
import io
import json
import os
from pathlib import Path
import sys

from typing import Dict, List, Tuple, Optional, Union

from clvm import SExp, to_sexp_f
from clvm.operators import OPERATOR_LOOKUP
from clvm.serialize import sexp_from_stream

from chia.util.config import load_config

from chia.types.blockchain_format.coin import Coin
from chia.types.blockchain_format.program import Program, INFINITE_COST
from chia.types.blockchain_format.sized_bytes import bytes32
from chia.types.spend_bundle import SpendBundle
from chia.types.coin_spend import CoinSpend
from chia.types.coin_record import CoinRecord
from chia.types.condition_opcodes import ConditionOpcode

from chia.consensus.default_constants import DEFAULT_CONSTANTS

from chia.rpc.rpc_client import RpcClient
from chia.rpc.full_node_rpc_client import FullNodeRpcClient
from chia.rpc.wallet_rpc_client import WalletRpcClient

from chia.util.config import load_config, save_config
from chia.util.hash import std_hash
from chia.util.ints import uint16, uint64

from chia.wallet.derive_keys import master_sk_to_wallet_sk, master_sk_to_wallet_sk_unhardened
from chia.wallet.lineage_proof import LineageProof
from chia.wallet.puzzles.load_clvm import load_clvm
from chia.wallet.puzzles.singleton_top_layer import (
    generate_launcher_coin,
    solution_for_singleton,
    SINGLETON_LAUNCHER,
    SINGLETON_LAUNCHER_HASH
)
from chia.wallet.puzzles.p2_delegated_puzzle_or_hidden_puzzle import (
    # standard_transaction
    puzzle_for_pk,
    calculate_synthetic_secret_key,
    calculate_synthetic_public_key,
    DEFAULT_HIDDEN_PUZZLE_HASH,
)
from chia.wallet.sign_coin_spends import sign_coin_spends

from cdv.test import SmartCoinWrapper, CoinPairSearch, CoinWrapper, Wallet

rpc_host = os.environ['CHIA_RPC_HOST'] if 'CHIA_RPC_HOST' in os.environ \
    else 'localhost'
full_node_rpc_port = os.environ['CHIA_RPC_PORT'] if 'CHIA_RPC_PORT' in os.environ \
    else '8555'
wallet_rpc_port = os.environ['CHIA_WALLET_PORT'] if 'CHIA_WALLET_PORT' in os.environ \
    else '9256'

def quote_program(x):
    return (1, x)

def plunge_path_in_config_(fname: Path, config: Dict, path: List[str]):
    """
    Simple conveniece for finding a path in a config and reporting precisely what
    was expected that is missing.
    """
    index = 0

    while True:
        if index >= len(path):
            return config
        else:
            if not path[index] in config or config[path[index]] is None:
                raise Exception(f'could not find value {"/".join(path[:index])} in config {fname}')

            config = config[path[index]]
            index += 1

def get_agg_sig_me_additional_data(root_path: Union[str, Path] = None) -> bytes:
    """
    Loads the correct value for the AGG_SIG_ME_ADDITIONAL_DATA constant
    and returns it so it can be used conveniently by API consumers.

    Raise exception if not found.
    """
    if root_path is None:
        if "CHIA_ROOT" in os.environ:
            root_path = Path(os.environ["CHIA_ROOT"])
        else:
            root_path = Path(os.environ["HOME"]) / ".chia/mainnet"
    else:
        root_path = Path(root_path)

    want_file = root_path / "config/config.yaml"

    config = load_config(root_path, "config.yaml", None)

    selected_network = plunge_path_in_config_(want_file, config, ["selected_network"])

    # if the network has a different AGG_SIG_ME_ADDITIONAL_DATA then use it,
    # otherwise the network uses mainnet's genesis challenge.
    try:
        agg_sig_me_additional_data = plunge_path_in_config_(
            want_file,
            config,
            ["farmer", "network_overrides", "constants", selected_network, "AGG_SIG_ME_ADDITIONAL_DATA"],
        )
    except Exception as e:
        # We can't get additional data, so we'll go with the mainnet genesis
        # challenge.
        agg_sig_me_additional_data = plunge_path_in_config_(
            want_file, config, ["farmer", "network_overrides", "constants", "mainnet", "GENESIS_CHALLENGE"]
        )

    return bytes(binascii.unhexlify(agg_sig_me_additional_data))

AGG_SIG_ME_ADDITIONAL_DATA = get_agg_sig_me_additional_data()

# A simple identity specification that allows pk_to_sk to work on the standard
# coin types we're aware of.
class Identity:
    def __init__(self,sk,pk,puzzle):
        self.sk = sk
        self.pk = pk
        self.puzzle = puzzle
        self.puzzle_hash = puzzle.get_tree_hash()

# A "wallet" like object that mediates access to the chia rpc services.
class CoinGrabber:
    def __init__(self):
        self.network = None
        self.wallet_rpc_client = None
        self.public_key_fingerprints = []
        self.puzzle = None
        self.puzzle_hash = None
        self.identities = []

    def __enter__(self):
        return self

    def __exit__(self,a,b,c):
        if self.network is not None:
            asyncio.run(self.network.await_closed())

        if self.wallet_rpc_client is not None:
            asyncio.run(self.wallet_rpc_client.await_closed())

    # Make connections to RPC services and set up internal state.
    async def start(self):
        root_dir = os.environ['CHIA_ROOT'] if 'CHIA_ROOT' in os.environ \
            else os.path.join(
                    os.environ['HOME'], '.chia/mainnet'
            )

        config = load_config(Path(root_dir), 'config.yaml')

        self.network = await FullNodeRpcClient.create(
            rpc_host, uint16(full_node_rpc_port), Path(root_dir), config
        )
        self.wallet_rpc_client = await WalletRpcClient.create(
            rpc_host, uint16(wallet_rpc_port), Path(root_dir), config
        )

        self.public_key_fingerprints = await self.wallet_rpc_client.get_public_keys()

        # Get usable coins
        wallets = await self.wallet_rpc_client.get_wallets()
        self.wallet = wallets[0]

        # Set up identity
        private_key = await self.wallet_rpc_client.get_private_key(self.public_key_fingerprints[0])

        sk_data = binascii.unhexlify(private_key['sk'])
        master_sk = PrivateKey.from_bytes(sk_data)
        master_pk = master_sk.get_g1()
        self.identities.append(Identity(
            master_sk,
            master_pk,
            puzzle_for_pk(master_pk)
        ))

        for i in range(1000):
            sk = master_sk_to_wallet_sk(master_sk, i)
            pk = sk.get_g1()
            self.identities.append(Identity(
                sk,
                pk,
                puzzle_for_pk(bytes(pk))
            ))

            sk = master_sk_to_wallet_sk_unhardened(master_sk, i)
            pk = sk.get_g1()
            self.identities.append(Identity(
                sk,
                pk,
                puzzle_for_pk(bytes(pk))
            ))


        transactions = await self.wallet_rpc_client.get_transactions(self.wallet['id'])

    # Return a specific coin with a hex name (as a string).
    async def get_coin(self,name):
        namelist = [bytes32(binascii.unhexlify(name))]
        result = await self.network.get_coin_records_by_names(
            namelist
        )
        return result

    # Using a given puzzle hash, determine an identity for this wallet to assume
    # when interacting with the blockchain.
    async def set_identity(self, puzzle_hash):
        for i in self.identities:
            if str(i.puzzle_hash) == str(puzzle_hash):
                self.sk_ = i.sk
                self.pk_ = i.pk
                self.puzzle = i.puzzle
                self.puzzle_hash = i.puzzle_hash
                return

        raise Exception('could not find identity for our coin')

    # Make a coin we can spend to create the singleton.  Change will be returned
    # to the same puzzle hash it came from.
    async def choose_coin(self, amt):
        """Given an amount requirement, find a coin that contains at least that much chia"""

        coins_to_spend = await self.wallet_rpc_client.select_coins(amount=amt,wallet_id=self.wallet['id'])

        # Couldn't find a working combination.
        if coins_to_spend is None or len(coins_to_spend) == 0:
            return None

        if len(coins_to_spend) == 1:
            only_coin: Coin = coins_to_spend[0]
            await self.set_identity(only_coin.puzzle_hash)

            return CoinWrapper(
                only_coin.parent_coin_info,
                only_coin.puzzle_hash,
                only_coin.amount,
                self.puzzle,
            )

        # We receive a timeline of actions to take (indicating that we have a plan)
        # Do the first action and start over.
        result: Optional[SpendResult] = await self.combine_coins(
            list(
                map(
                    lambda x: CoinWrapper(x.parent_coin_info, x.puzzle_hash, x.amount, self.puzzle),
                    coins_to_spend,
                )
            )
        )

        if result is None:
            return None

        assert self.balance() == start_balance
        return await self.choose_coin(amt)

    def pk_to_sk(self,pk):
        for i in self.identities:
            if str(i.pk) == str(pk):
                return i.sk

            synthetic_pk = calculate_synthetic_public_key(i.pk, DEFAULT_HIDDEN_PUZZLE_HASH)
            if str(synthetic_pk) == str(pk):
                return calculate_synthetic_secret_key(i.sk, DEFAULT_HIDDEN_PUZZLE_HASH)
        return None

    # A generic spender for various kinds of coins, specified in various ways.
    async def spend_coin(self, coin, pushtx: bool = True, debug: bool = False, **kwargs):
        """Given a coin object, invoke it on the blockchain, either as a standard
        coin if no arguments are given or with custom arguments in args="""

        amt = uint64(1)
        if "amt" in kwargs:
            amt = kwargs["amt"]

        if "puzzle" in kwargs:
            puzzle = kwargs["puzzle"]
        else:
            puzzle = coin.puzzle()

        delegated_puzzle_solution: Optional[Program] = None
        if "args" not in kwargs:
            target_puzzle_hash: bytes32 = self.puzzle_hash
            # Allow the user to 'give this much chia' to another user.
            if "to" in kwargs:
                toward: Union[bytes32, Wallet] = kwargs["to"]
                if isinstance(toward, bytes32):
                    target_puzzle_hash = toward
                else:
                    target_puzzle_hash = kwargs["to"].puzzle_hash

            # Automatic arguments from the user's intention.
            if "custom_conditions" not in kwargs:
                solution_list: List[List] = [[ConditionOpcode.CREATE_COIN, target_puzzle_hash, amt]]
            else:
                solution_list = kwargs["custom_conditions"]

            if "remain" in kwargs:
                remainer: Union[SmartCoinWrapper, Wallet] = kwargs["remain"]
                remain_amt = uint64(coin.amount - amt)
                if isinstance(remainer, SmartCoinWrapper):
                    solution_list.append(
                        [
                            ConditionOpcode.CREATE_COIN,
                            remainer.puzzle_hash(),
                            remain_amt,
                        ]
                    )
                elif hasattr(remainer, 'puzzle_hash'):
                    solution_list.append([ConditionOpcode.CREATE_COIN, remainer.puzzle_hash, remain_amt])
                else:
                    raise ValueError("remainer is not a wallet or a smart coin")

            #
            # A note about what's going on here:
            #
            #  The standard coin is a 'delegated puzzle', and takes 3 arguments,
            #  - Either () in the delegated case or a secret key if the puzzle is hidden.
            #  - Code to run to generate conditions if the spend is allowed (a 'delegated'
            #    puzzle.  The puzzle given here quotes the desired conditions.
            #  - A 'solution' to the given puzzle: since this puzzle does not use its
            #    arguments, the argument list is empty.
            #
            delegated_puzzle_solution = Program.to(quote_program(solution_list))
            # Solution is the solution for the old coin.
            solution = Program.to([[], delegated_puzzle_solution, []])
        else:
            delegated_puzzle_solution = Program.to(kwargs["args"])
            solution = delegated_puzzle_solution

        puzzle_hash = puzzle.get_tree_hash()

        use_coin = coin
        if hasattr(coin, 'as_coin'):
            use_coin = coin.as_coin()

        solution_for_coin = CoinSpend(
            use_coin,
            puzzle,
            solution,
        )

        try:
            sign_coin_spend_args = [
                [solution_for_coin],
                lambda pk: self.pk_to_sk(pk),
                AGG_SIG_ME_ADDITIONAL_DATA,
                DEFAULT_CONSTANTS.MAX_BLOCK_COST_CLVM,
            ]
            spend_bundle: SpendBundle = await sign_coin_spends(
                *sign_coin_spend_args
            )

        except Exception as e:
            print('exception',e.args)
            print('our pk is %s' % self.pk_)
            print('our sk is %s' % self.sk_)
            raise e

        if debug:
            spend_bundle.debug()

        if pushtx:
            pushed: Dict[str, Union[str, List[Coin]]] = await self.network.push_tx(spend_bundle)
            return pushed
        else:
            return spend_bundle

    async def push_tx(self,bundle):
        pushed: Dict[str, Union[str, List[Coin]]] = await self.network.push_tx(bundle)
        return pushed

# Simple function to read a program from a file containing hex.
def read_hex_program(filename):
    stream = io.BytesIO(binascii.unhexlify(open(filename).read().strip()))
    return sexp_from_stream(stream, to_sexp_f)

# Simple function to use a program in a string containing hex.
def use_hex_program(data):
    stream = io.BytesIO(binascii.unhexlify(data))
    return sexp_from_stream(stream, to_sexp_f)

# more generic version of launch_conditions_and_coinsol
def bespoke_launch_conditions_and_coinsol(
    singleton_mod,
    coin: Coin,
    inner_puzzle: Program,
    comment: List[Tuple[str, str]],
    amount: uint64,
) -> Tuple[List[Program], CoinSpend]:
    singleton_mod_hash = Program.to(singleton_mod).get_tree_hash()

    if (amount % 2) == 0:
        raise ValueError("Coin amount cannot be even. Subtract one mojo.")

    launcher_coin: Coin = generate_launcher_coin(coin, amount)
    curried_singleton: Program = singleton_mod.curry(
        (singleton_mod_hash, (launcher_coin.name(), SINGLETON_LAUNCHER_HASH)),
        inner_puzzle,
    )

    launcher_solution = Program.to(
        [
            curried_singleton.get_tree_hash(),
            amount,
            comment,
        ]
    )
    create_launcher = Program.to(
        [
            ConditionOpcode.CREATE_COIN,
            SINGLETON_LAUNCHER_HASH,
            amount,
        ],
    )
    assert_launcher_announcement = Program.to(
        [
            ConditionOpcode.ASSERT_COIN_ANNOUNCEMENT,
            std_hash(launcher_coin.name() + launcher_solution.get_tree_hash()),
        ],
    )

    conditions = [create_launcher, assert_launcher_announcement]

    launcher_coin_spend = CoinSpend(
        launcher_coin,
        SINGLETON_LAUNCHER,
        launcher_solution,
    )

    return conditions, launcher_coin_spend

# Return the puzzle reveal of a singleton with specific ID and innerpuz
def bespoke_puzzle_for_singleton(singleton: Program, launcher_id: bytes32, inner_puz: Program) -> Program:
    return singleton.curry(
        (singleton.get_tree_hash(), (launcher_id, SINGLETON_LAUNCHER_HASH)),
        inner_puz,
    )

# High level overview of singleton creation.
async def create_singleton_with_program(cg,argres):
    amount = int(argres.amount) if argres.amount is not None else 1
    program = read_hex_program(argres.create_singleton_with_program)
    singleton = Program.to(read_hex_program(argres.singleton))
    start_coin = await cg.choose_coin(amount)
    conditions, spend = bespoke_launch_conditions_and_coinsol(
        singleton,
        start_coin,
        program,
        [],
        amount
    )

    conditions.append([51, cg.puzzle_hash, start_coin.amount - amount])

    print(f'spend coin with puzzle {cg.puzzle_hash}')
    launch_coin_spend_into_singleton_launcher = await cg.spend_coin(
        start_coin,
        amt=amount,
        puzzle=cg.puzzle,
        args=Program.to([[], quote_program(conditions), []]),
        to=Program.fromhex(str(spend.puzzle_reveal)).get_tree_hash(),
        pushtx=False
    )

    launch_coin_spend_into_singleton_launcher.coin_spends.append(spend)
    launch_coin_spend_into_singleton_launcher.debug()
    print(launch_coin_spend_into_singleton_launcher)
    await cg.network.push_tx(launch_coin_spend_into_singleton_launcher)

    singleton_launcher = Coin(start_coin.name(), SINGLETON_LAUNCHER_HASH, amount)
    singleton_program = singleton.curry(
        (singleton.get_tree_hash(), (singleton_launcher.name(), SINGLETON_LAUNCHER_HASH)),
        program
    )
    completed_singleton = Coin(singleton_launcher.name(), singleton_program.get_tree_hash(), amount)
    print(f'new puzzle hash: {singleton_program.get_tree_hash()}')
    print(f'completed singleton: {completed_singleton.name()}')

# Show the puzzle hash we predict the first singleton will have, given current
# conditions.
async def show_initial_puzzle_hash(cg,argres):
    amount = int(argres.amount) if argres.amount is not None else 1
    program = read_hex_program(argres.show_initial_puzzle_hash)
    singleton = Program.to(read_hex_program(argres.singleton))
    start_coin = await cg.choose_coin(1)
    conditions, spend = bespoke_launch_conditions_and_coinsol(
        singleton,
        start_coin,
        program,
        [],
        amount
    )

    launch_coin_spend_into_singleton_launcher = await cg.spend_coin(
        start_coin,
        amt=amount,
        puzzle=cg.puzzle,
        args=Program.to([[], quote_program(conditions), []]),
        to=Program.fromhex(str(spend.puzzle_reveal)).get_tree_hash(),
        pushtx=False
    )

    launch_coin_spend_into_singleton_launcher.coin_spends.append(spend)
    singleton_launcher = Coin(start_coin.name(), SINGLETON_LAUNCHER_HASH, amount)
    singleton_program = singleton.curry(singleton, program)
    print(f'{singleton_program.get_tree_hash()}')

# Spend a singleton identified by coin name (hex) into another singleton.
async def continue_singleton(cg,argres):
    if argres.inner_solution is None:
        print('specify a hex solution with --inner-solution')
        sys.exit(1)

    if argres.inner_puzzle is None:
        print('specify a hex program file with --inner-puzzle')
        sys.exit(1)

    program = read_hex_program(argres.inner_puzzle)
    singleton = Program.to(read_hex_program(argres.singleton))

    coinid = argres.continue_singleton
    coins = await cg.get_coin(coinid)
    if len(coins) == 0:
        print(f'no such coin {coinid}')
        sys.exit(1)

    coin = coins[0].coin

    # Find launcher, stop when we find a coin whose puzzle hash is
    # SINGLETON_LAUNCHER_HASH
    search_coin = coin
    coins = await cg.get_coin(str(search_coin.parent_coin_info))

    if len(coins) != 0:
        parent_coin = coins[0].coin
    else:
        print(f'could not locate parent of coin to spend')
        sys.exit(1)

    while len(coins) and str(coins[0].coin.puzzle_hash) != str(SINGLETON_LAUNCHER_HASH):
        search_coin = coins[0].coin
        coins = await cg.get_coin(str(search_coin.parent_coin_info))

    if len(coins) == 0:
        print('could not search out the launcher')
        sys.exit(1)

    launcher = coins[0].coin
    print(f'found launcher {launcher.name()}')

    # Use the launcher's parent to bootstrap identity
    parent_of_launcher = await cg.get_coin(str(launcher.parent_coin_info))
    if len(parent_of_launcher) == 0:
        print(f'launcher was born from the ether')
        sys.exit(1)

    identity_coin = parent_of_launcher[0].coin
    await cg.set_identity(identity_coin.puzzle_hash)

    # Determine arguments to use for continuing the singleton
    use_puzzle_hash = Program.to(program).get_tree_hash() if parent_coin.name() != launcher.name() else None
    singleton_program = bespoke_puzzle_for_singleton(
        singleton,
        launcher.name(),
        program
    )
    solution = solution_for_singleton(
        LineageProof(
            parent_coin.parent_coin_info,
            use_puzzle_hash,
            parent_coin.amount
        ),
        coin.amount,
        Program.to(use_hex_program(argres.inner_solution))
    )
    new_puzzle_hash = singleton_program.get_tree_hash()
    await cg.spend_coin(
        coin,
        coin.amount,
        puzzle=singleton_program,
        args=solution,
        to=new_puzzle_hash
    )

    new_singleton_coin = Coin(coin.name(), new_puzzle_hash, coin.amount)
    print(f'new puzzle hash: {new_puzzle_hash}')
    print(f'continued singleton: {new_singleton_coin.name()}')

async def main(cg,args):
    parser = argparse.ArgumentParser()
    parser.add_argument('--create-singleton-with-program',type=str, default=None)
    parser.add_argument('--show-initial-puzzle-hash',type=str, default=None)
    parser.add_argument('--continue-singleton',type=str, default=None)
    parser.add_argument('--inner-puzzle', type=str, default=None)
    parser.add_argument('--inner-solution', type=str, default=None)
    parser.add_argument('--singleton', type=str, default=None)
    parser.add_argument('--amount', type=int, default=None)
    argres = parser.parse_args(args[1:])

    if argres.singleton is None:
        print('use --singleton to specify a compiled singleton (in hex)')
        sys.exit(1)

    await cg.start()

    if argres.create_singleton_with_program is not None:
        await create_singleton_with_program(cg,argres)
    elif argres.show_initial_puzzle_hash is not None:
        await show_initial_puzzle_hash(cg,argres)
    elif argres.continue_singleton is not None:
        await continue_singleton(cg,argres)
    else:
        print('specify one of')
        print('--create-singleton-with-program=program.clvm')
        print('--show-initial-puzzle-hash=program.clvm')
        print('--continue-singleton=coinid')
        sys.exit(1)

if __name__ == '__main__':
    with CoinGrabber() as cg:
        asyncio.run(main(cg, sys.argv))
