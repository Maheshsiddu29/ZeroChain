use crate::{mock::*, Error, Event, OriginRoots, ProcessedNonces, ProcessedMessages, MessageCount, ChainCount};
use frame_support::{assert_noop, assert_ok};
use zk_types::{BridgeMessage, BridgeOriginInputs, BridgeHandler};

fn state_root(seed: u8) -> [u8; 32] { [seed; 32] }
fn msg_hash(seed: u8) -> [u8; 32] { [seed; 32] }

fn make_message(chain_id: u32, nonce: u64, hash_seed: u8) -> BridgeMessage {
    BridgeMessage {
        source_chain_id: chain_id,
        message_hash: msg_hash(hash_seed),
        payload: vec![0xDE, 0xAD],
        nonce,
    }
}

fn make_inputs(chain_id: u32, root_seed: u8, hash_seed: u8, nonce: u64) -> BridgeOriginInputs {
    BridgeOriginInputs {
        source_chain_id: chain_id,
        source_state_root: state_root(root_seed),
        message_hash: msg_hash(hash_seed),
        nonce,
    }
}

// ─── register_source_chain tests ─────────────────────────────

#[test]
fn register_source_chain_works() {
    new_test_ext().execute_with(|| {
        let root = state_root(0xAA);
        assert_ok!(ZkBridge::register_source_chain(RuntimeOrigin::root(), 1, root));
        assert_eq!(OriginRoots::<Test>::get(1), Some(root));
        assert_eq!(ChainCount::<Test>::get(), 1);
        System::assert_last_event(Event::SourceChainRegistered { chain_id: 1, state_root: root }.into());
    });
}

#[test]
fn register_source_chain_requires_root() {
    new_test_ext().execute_with(|| {
        assert_noop!(
            ZkBridge::register_source_chain(RuntimeOrigin::signed(1), 1, state_root(0xBB)),
            sp_runtime::DispatchError::BadOrigin
        );
    });
}

#[test]
fn register_source_chain_rejects_duplicate() {
    new_test_ext().execute_with(|| {
        assert_ok!(ZkBridge::register_source_chain(RuntimeOrigin::root(), 1, state_root(0xCC)));
        assert_noop!(
            ZkBridge::register_source_chain(RuntimeOrigin::root(), 1, state_root(0xDD)),
            Error::<Test>::ChainAlreadyRegistered
        );
    });
}

// ─── update_origin_root tests ────────────────────────────────

#[test]
fn update_origin_root_works() {
    new_test_ext().execute_with(|| {
        assert_ok!(ZkBridge::register_source_chain(RuntimeOrigin::root(), 1, state_root(0xAA)));
        let new_root = state_root(0xBB);
        assert_ok!(ZkBridge::update_origin_root(RuntimeOrigin::root(), 1, new_root));
        assert_eq!(OriginRoots::<Test>::get(1), Some(new_root));
        System::assert_last_event(Event::OriginRootUpdated { chain_id: 1, new_root }.into());
    });
}

#[test]
fn update_origin_root_rejects_unknown_chain() {
    new_test_ext().execute_with(|| {
        assert_noop!(
            ZkBridge::update_origin_root(RuntimeOrigin::root(), 99, state_root(0xFF)),
            Error::<Test>::UnknownSourceChain
        );
    });
}

// ─── submit_bridge_message tests ─────────────────────────────

#[test]
fn submit_message_works() {
    new_test_ext().execute_with(|| {
        let root = state_root(0xAA);
        assert_ok!(ZkBridge::register_source_chain(RuntimeOrigin::root(), 1, root));

        let msg = make_message(1, 1, 0x11);
        let inputs = make_inputs(1, 0xAA, 0x11, 1);

        assert_ok!(ZkBridge::submit_bridge_message(RuntimeOrigin::signed(1), msg.clone(), inputs));
        assert_eq!(MessageCount::<Test>::get(), 1);
        assert_eq!(ProcessedNonces::<Test>::get(1), 1);
        assert!(ProcessedMessages::<Test>::contains_key(&msg.message_hash));
        System::assert_last_event(Event::MessageProcessed {
            source_chain_id: 1,
            message_hash: msg.message_hash,
            nonce: 1,
        }.into());
    });
}

#[test]
fn submit_message_rejects_unknown_chain() {
    new_test_ext().execute_with(|| {
        let msg = make_message(99, 1, 0x22);
        let inputs = make_inputs(99, 0xBB, 0x22, 1);
        assert_noop!(
            ZkBridge::submit_bridge_message(RuntimeOrigin::signed(1), msg, inputs),
            Error::<Test>::UnknownSourceChain
        );
    });
}

#[test]
fn submit_message_rejects_wrong_state_root() {
    new_test_ext().execute_with(|| {
        assert_ok!(ZkBridge::register_source_chain(RuntimeOrigin::root(), 1, state_root(0xAA)));

        let msg = make_message(1, 1, 0x33);
        let inputs = make_inputs(1, 0xFF, 0x33, 1); // wrong root
        assert_noop!(
            ZkBridge::submit_bridge_message(RuntimeOrigin::signed(1), msg, inputs),
            Error::<Test>::OriginRootMismatch
        );
    });
}

#[test]
fn submit_message_rejects_out_of_order_nonce() {
    new_test_ext().execute_with(|| {
        assert_ok!(ZkBridge::register_source_chain(RuntimeOrigin::root(), 1, state_root(0xAA)));

        let msg = make_message(1, 5, 0x44); // nonce 5, expected 1
        let inputs = make_inputs(1, 0xAA, 0x44, 5);
        assert_noop!(
            ZkBridge::submit_bridge_message(RuntimeOrigin::signed(1), msg, inputs),
            Error::<Test>::NonceOutOfOrder
        );
    });
}

#[test]
fn submit_message_rejects_duplicate() {
    new_test_ext().execute_with(|| {
        assert_ok!(ZkBridge::register_source_chain(RuntimeOrigin::root(), 1, state_root(0xAA)));

        let msg = make_message(1, 1, 0x55);
        let inputs = make_inputs(1, 0xAA, 0x55, 1);
        assert_ok!(ZkBridge::submit_bridge_message(RuntimeOrigin::signed(1), msg.clone(), inputs.clone()));

        // same message again with nonce 2
        let msg2 = BridgeMessage { nonce: 2, ..msg.clone() };
        let inputs2 = BridgeOriginInputs { nonce: 2, ..inputs };
        assert_noop!(
            ZkBridge::submit_bridge_message(RuntimeOrigin::signed(1), msg2, inputs2),
            Error::<Test>::MessageAlreadyProcessed
        );
    });
}

#[test]
fn submit_message_rejects_oversized_payload() {
    new_test_ext().execute_with(|| {
        assert_ok!(ZkBridge::register_source_chain(RuntimeOrigin::root(), 1, state_root(0xAA)));

        let msg = BridgeMessage {
            source_chain_id: 1,
            message_hash: msg_hash(0x66),
            payload: vec![0u8; 5000], // exceeds MaxPayloadSize=4096
            nonce: 1,
        };
        let inputs = make_inputs(1, 0xAA, 0x66, 1);
        assert_noop!(
            ZkBridge::submit_bridge_message(RuntimeOrigin::signed(1), msg, inputs),
            Error::<Test>::PayloadTooLarge
        );
    });
}

// ─── sequential nonce test ───────────────────────────────────

#[test]
fn sequential_messages_work() {
    new_test_ext().execute_with(|| {
        assert_ok!(ZkBridge::register_source_chain(RuntimeOrigin::root(), 1, state_root(0xAA)));

        for i in 1..=5u64 {
            let msg = make_message(1, i, i as u8);
            let inputs = make_inputs(1, 0xAA, i as u8, i);
            assert_ok!(ZkBridge::submit_bridge_message(RuntimeOrigin::signed(1), msg, inputs));
        }

        assert_eq!(MessageCount::<Test>::get(), 5);
        assert_eq!(ProcessedNonces::<Test>::get(1), 5);
    });
}

// ─── multi-chain test ────────────────────────────────────────

#[test]
fn multi_chain_messages_work() {
    new_test_ext().execute_with(|| {
        assert_ok!(ZkBridge::register_source_chain(RuntimeOrigin::root(), 1, state_root(0xAA)));
        assert_ok!(ZkBridge::register_source_chain(RuntimeOrigin::root(), 2, state_root(0xBB)));
        assert_eq!(ChainCount::<Test>::get(), 2);

        // message from chain 1
        let msg1 = make_message(1, 1, 0x11);
        let inputs1 = make_inputs(1, 0xAA, 0x11, 1);
        assert_ok!(ZkBridge::submit_bridge_message(RuntimeOrigin::signed(1), msg1, inputs1));

        // message from chain 2
        let msg2 = make_message(2, 1, 0x22);
        let inputs2 = make_inputs(2, 0xBB, 0x22, 1);
        assert_ok!(ZkBridge::submit_bridge_message(RuntimeOrigin::signed(1), msg2, inputs2));

        assert_eq!(MessageCount::<Test>::get(), 2);
        assert_eq!(ProcessedNonces::<Test>::get(1), 1);
        assert_eq!(ProcessedNonces::<Test>::get(2), 1);
    });
}

// ─── BridgeHandler trait test ────────────────────────────────

#[test]
fn process_verified_message_via_trait() {
    new_test_ext().execute_with(|| {
        assert_ok!(ZkBridge::register_source_chain(RuntimeOrigin::root(), 1, state_root(0xAA)));

        let msg = make_message(1, 1, 0x77);
        let inputs = make_inputs(1, 0xAA, 0x77, 1);

        <ZkBridge as BridgeHandler>::process_verified_message(&msg, &inputs);
        assert!(ProcessedMessages::<Test>::contains_key(&msg.message_hash));
        assert_eq!(MessageCount::<Test>::get(), 1);
    });
}

#[test]
fn process_verified_message_idempotent() {
    new_test_ext().execute_with(|| {
        assert_ok!(ZkBridge::register_source_chain(RuntimeOrigin::root(), 1, state_root(0xAA)));

        let msg = make_message(1, 1, 0x88);
        let inputs = make_inputs(1, 0xAA, 0x88, 1);

        <ZkBridge as BridgeHandler>::process_verified_message(&msg, &inputs);
        <ZkBridge as BridgeHandler>::process_verified_message(&msg, &inputs);
        // should only count once
        assert_eq!(MessageCount::<Test>::get(), 1);
    });
}

// ─── full lifecycle test ─────────────────────────────────────

#[test]
fn full_bridge_lifecycle() {
    new_test_ext().execute_with(|| {
        // register ethereum (chain 1) and cosmos (chain 2)
        assert_ok!(ZkBridge::register_source_chain(RuntimeOrigin::root(), 1, state_root(0xE1)));
        assert_ok!(ZkBridge::register_source_chain(RuntimeOrigin::root(), 2, state_root(0xC0)));

        // ethereum sends 3 messages
        for i in 1..=3u64 {
            let msg = make_message(1, i, (0xE0 + i) as u8);
            let inputs = make_inputs(1, 0xE1, (0xE0 + i) as u8, i);
            assert_ok!(ZkBridge::submit_bridge_message(RuntimeOrigin::signed(1), msg, inputs));
        }

        // cosmos sends 2 messages
        for i in 1..=2u64 {
            let msg = make_message(2, i, (0xC0 + i) as u8);
            let inputs = make_inputs(2, 0xC0, (0xC0 + i) as u8, i);
            assert_ok!(ZkBridge::submit_bridge_message(RuntimeOrigin::signed(1), msg, inputs));
        }

        // update ethereum state root (simulating state progression)
        assert_ok!(ZkBridge::update_origin_root(RuntimeOrigin::root(), 1, state_root(0xE2)));

        // new message with updated root
        let msg = make_message(1, 4, 0xE4);
        let inputs = make_inputs(1, 0xE2, 0xE4, 4);
        assert_ok!(ZkBridge::submit_bridge_message(RuntimeOrigin::signed(1), msg, inputs));

        assert_eq!(MessageCount::<Test>::get(), 6);
        assert_eq!(ProcessedNonces::<Test>::get(1), 4);
        assert_eq!(ProcessedNonces::<Test>::get(2), 2);
        assert_eq!(ChainCount::<Test>::get(), 2);
    });
}