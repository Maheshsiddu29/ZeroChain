use crate as pallet_shielded_assets;
use frame_support::derive_impl;
use frame_support::traits::VariantCountOf;
use sp_runtime::BuildStorage;

pub type Balance = u128;

type Block = frame_system::mocking::MockBlock<Test>;

#[frame_support::runtime]
mod runtime {
    #[runtime::runtime]
    #[runtime::derive(
        RuntimeCall,
        RuntimeEvent,
        RuntimeError,
        RuntimeOrigin,
        RuntimeFreezeReason,
        RuntimeHoldReason,
        RuntimeSlashReason,
        RuntimeLockId,
        RuntimeTask,
        RuntimeViewFunction
    )]
    pub struct Test;

    #[runtime::pallet_index(0)]
    pub type System = frame_system::Pallet<Test>;

    #[runtime::pallet_index(1)]
    pub type ShieldedAssets = pallet_shielded_assets::Pallet<Test>;

    #[runtime::pallet_index(2)]
    pub type Balances = pallet_balances::Pallet<Test>;
}

#[derive_impl(frame_system::config_preludes::TestDefaultConfig)]
impl frame_system::Config for Test {
    type Block = Block;
    type AccountData = pallet_balances::AccountData<Balance>;
}

impl pallet_balances::Config for Test {
    type MaxLocks = frame_support::traits::ConstU32<50>;
    type MaxReserves = ();
    type ReserveIdentifier = [u8; 8];
    type Balance = Balance;
    type RuntimeEvent = RuntimeEvent;
    type DustRemoval = ();
    type ExistentialDeposit = frame_support::traits::ConstU128<1>;
    type AccountStore = System;
    type WeightInfo = ();
    type FreezeIdentifier = RuntimeFreezeReason;
    type MaxFreezes = VariantCountOf<RuntimeFreezeReason>;
    type RuntimeHoldReason = RuntimeHoldReason;
    type RuntimeFreezeReason = RuntimeFreezeReason;
    type DoneSlashHandler = ();
}

impl pallet_shielded_assets::Config for Test {
    type MaxCommitments = frame_support::traits::ConstU32<1048576>;
    type MerkleRootHistory = frame_support::traits::ConstU32<32>;
    type Currency = Balances;
}

/// Build test externalities with an initial Merkle root so transfers work
/// without needing `update_merkle_root` calls in most tests.
pub fn new_test_ext_with_root(root: [u8; 32]) -> sp_io::TestExternalities {
    let genesis = crate::pallet::GenesisConfig::<Test> {
        initial_merkle_root: Some(root),
        _phantom: Default::default(),
    };
    let mut storage = frame_system::GenesisConfig::<Test>::default()
        .build_storage()
        .unwrap();
    genesis.assimilate_storage(&mut storage).unwrap();
    let mut ext: sp_io::TestExternalities = storage.into();
    ext.execute_with(|| System::set_block_number(1));
    ext
}

/// Build test externalities with NO initial root (for testing the NoMerkleRoot path).
pub fn new_test_ext() -> sp_io::TestExternalities {
    let t = frame_system::GenesisConfig::<Test>::default()
        .build_storage()
        .unwrap();
    let mut ext: sp_io::TestExternalities = t.into();
    ext.execute_with(|| System::set_block_number(1));
    ext
}

/// Build test externalities with pre-funded accounts but no initial Merkle root.
pub fn new_test_ext_with_balances(balances: Vec<(u64, Balance)>) -> sp_io::TestExternalities {
    let mut storage = frame_system::GenesisConfig::<Test>::default()
        .build_storage()
        .unwrap();
    pallet_balances::GenesisConfig::<Test> { balances, dev_accounts: None }
        .assimilate_storage(&mut storage)
        .unwrap();
    let mut ext: sp_io::TestExternalities = storage.into();
    ext.execute_with(|| System::set_block_number(1));
    ext
}

/// Build test externalities with pre-funded accounts AND an initial Merkle root.
pub fn new_test_ext_with_balances_and_root(
    balances: Vec<(u64, Balance)>,
    root: [u8; 32],
) -> sp_io::TestExternalities {
    let mut storage = frame_system::GenesisConfig::<Test>::default()
        .build_storage()
        .unwrap();
    pallet_balances::GenesisConfig::<Test> { balances, dev_accounts: None }
        .assimilate_storage(&mut storage)
        .unwrap();
    crate::pallet::GenesisConfig::<Test> {
        initial_merkle_root: Some(root),
        _phantom: Default::default(),
    }
    .assimilate_storage(&mut storage)
    .unwrap();
    let mut ext: sp_io::TestExternalities = storage.into();
    ext.execute_with(|| System::set_block_number(1));
    ext
}
