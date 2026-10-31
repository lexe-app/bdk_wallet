use std::collections::HashSet;
use std::str::FromStr;

use assert_matches::assert_matches;
use bdk_chain::{BlockId, ConfirmationBlockTime, Merge};
use bdk_wallet::descriptor::IntoWalletDescriptor;
use bdk_wallet::export::FullyNodedExport;
use bdk_wallet::signer::SignOptions;
use bdk_wallet::template::{Bip84, Bip86};
use bdk_wallet::test_utils::*;
use bdk_wallet::{ChangeSet, CreateParams, KeychainKind, LoadError, LoadMismatch, Wallet};
use bitcoin::bip32::Xpriv;
use bitcoin::hashes::Hash;
use bitcoin::key::Secp256k1;
use bitcoin::{Address, Amount, BlockHash, Network, OutPoint, Psbt};

const XPRV: &str = "tprv8ZgxMBicQKsPeZRHk4rTG6orPS2CRNFX3njhUXx5vj9qGog5ZMH4uGReDWN5kCkY3jmWEtWause41CDvBRXD1shKknAMKxT99o9qUTRVC6m";
const RECIPIENT: &str = "bcrt1q3qtze4ys45tgdvguj66zrk4fu6hq3a3v9pfly5";

fn xprv() -> Xpriv {
    Xpriv::from_str(XPRV).unwrap()
}

fn bip84(keychain: KeychainKind) -> Bip84<Xpriv> {
    Bip84(xprv(), keychain)
}

fn recipient() -> Address {
    Address::from_str(RECIPIENT).unwrap().assume_checked()
}

/// A wallet with all three keychains.
fn three_keychain_wallet() -> Wallet {
    wallet_with_tip(
        CreateParams::new(bip84(KeychainKind::External), bip84(KeychainKind::Internal))
            .single_use_descriptor(bip84(KeychainKind::SingleUse)),
    )
}

/// Creates a regtest wallet with a non-genesis tip to confirm txs in.
fn wallet_with_tip(params: CreateParams) -> Wallet {
    let mut wallet = params
        .network(Network::Regtest)
        .create_wallet_no_persist()
        .unwrap();
    insert_checkpoint(
        &mut wallet,
        BlockId {
            height: 100,
            hash: BlockHash::all_zeros(),
        },
    );
    wallet
}

/// Receives a confirmed output to a newly revealed address of `keychain`.
fn fund(wallet: &mut Wallet, keychain: KeychainKind, sats: u64) -> OutPoint {
    let addr = wallet.reveal_next_address(keychain);
    assert_eq!(addr.keychain, keychain);
    let anchor = ConfirmationBlockTime {
        block_id: wallet.latest_checkpoint().block_id(),
        confirmation_time: 0,
    };
    receive_output_to_address(wallet, addr.address, Amount::from_sat(sats), anchor)
}

fn input_outpoints(psbt: &Psbt) -> HashSet<OutPoint> {
    psbt.unsigned_tx
        .input
        .iter()
        .map(|txin| txin.previous_output)
        .collect()
}

/// The keychains of all outputs not paying `recipient()`.
fn change_keychains(wallet: &Wallet, psbt: &Psbt) -> Vec<Option<(KeychainKind, u32)>> {
    psbt.unsigned_tx
        .output
        .iter()
        .filter(|txout| txout.script_pubkey != recipient().script_pubkey())
        .map(|txout| wallet.derivation_of_spk(txout.script_pubkey.clone()))
        .collect()
}

#[test]
fn single_use_addresses_derive_from_keychain_2() {
    let mut wallet = three_keychain_wallet();

    let secp = Secp256k1::new();
    let (expected_desc, _) = format!("wpkh({XPRV}/84'/1'/0'/2/*)")
        .into_wallet_descriptor(&secp, Network::Regtest)
        .unwrap();
    for index in 0..3 {
        let addr = wallet.reveal_next_address(KeychainKind::SingleUse);
        assert_eq!(addr.keychain, KeychainKind::SingleUse);
        assert_eq!(addr.index, index);

        let expected_spk = expected_desc
            .at_derivation_index(index)
            .unwrap()
            .script_pubkey();
        assert_eq!(addr.script_pubkey(), expected_spk);
        assert_eq!(
            wallet.derivation_of_spk(expected_spk),
            Some((KeychainKind::SingleUse, index)),
        );
    }
    assert_eq!(wallet.derivation_index(KeychainKind::SingleUse), Some(2));
    assert_eq!(wallet.derivation_index(KeychainKind::External), None);
}

#[test]
fn spend_mixing_single_use_and_external_utxos() {
    let mut wallet = three_keychain_wallet();
    let single_use = fund(&mut wallet, KeychainKind::SingleUse, 30_000);
    let external = fund(&mut wallet, KeychainKind::External, 30_000);
    assert_eq!(wallet.balance().confirmed, Amount::from_sat(60_000));

    let mut builder = wallet.build_tx();
    builder.add_recipient(recipient().script_pubkey(), Amount::from_sat(50_000));
    let mut psbt = builder.finish().unwrap();
    assert_eq!(input_outpoints(&psbt), [single_use, external].into());

    let finalized = wallet.sign(&mut psbt, SignOptions::default()).unwrap();
    assert!(finalized, "both inputs must be signed by the one wallet");

    assert_matches!(
        change_keychains(&wallet, &psbt).as_slice(),
        [Some((KeychainKind::Internal, _))]
    );
}

#[test]
fn change_spend_policy_treats_single_use_as_non_change() {
    let mut wallet = three_keychain_wallet();
    let single_use = fund(&mut wallet, KeychainKind::SingleUse, 10_000);
    let external = fund(&mut wallet, KeychainKind::External, 10_000);
    let internal = fund(&mut wallet, KeychainKind::Internal, 10_000);

    let mut builder = wallet.build_tx();
    builder
        .drain_wallet()
        .drain_to(recipient().script_pubkey())
        .do_not_spend_change();
    let psbt = builder.finish().unwrap();
    assert_eq!(input_outpoints(&psbt), [single_use, external].into());

    let mut builder = wallet.build_tx();
    builder
        .drain_wallet()
        .drain_to(recipient().script_pubkey())
        .only_spend_change();
    let psbt = builder.finish().unwrap();
    assert_eq!(input_outpoints(&psbt), [internal].into());
}

#[test]
fn single_use_without_change_keychain() {
    let mut wallet = wallet_with_tip(
        CreateParams::new_single(bip84(KeychainKind::External))
            .single_use_descriptor(bip84(KeychainKind::SingleUse)),
    );

    // The absent internal keychain maps to external.
    let addr = wallet.reveal_next_address(KeychainKind::Internal);
    assert_eq!(addr.keychain, KeychainKind::External);

    let single_use = fund(&mut wallet, KeychainKind::SingleUse, 30_000);

    // Without a change keychain, the change spend policy is ignored.
    let mut builder = wallet.build_tx();
    builder
        .drain_wallet()
        .drain_to(recipient().script_pubkey())
        .only_spend_change();
    let psbt = builder.finish().unwrap();
    assert_eq!(input_outpoints(&psbt), [single_use].into());

    let mut builder = wallet.build_tx();
    builder.add_recipient(recipient().script_pubkey(), Amount::from_sat(10_000));
    let mut psbt = builder.finish().unwrap();
    assert!(wallet.sign(&mut psbt, SignOptions::default()).unwrap());

    assert_matches!(
        change_keychains(&wallet, &psbt).as_slice(),
        [Some((KeychainKind::External, _))]
    );
}

#[test]
fn changeset_serde_roundtrip() {
    let mut wallet = three_keychain_wallet();
    let changeset = wallet.take_staged().unwrap();
    assert!(changeset.single_use_descriptor.is_some());

    let json = serde_json::to_string(&changeset).unwrap();
    assert_eq!(serde_json::from_str::<ChangeSet>(&json).unwrap(), changeset);

    // Changesets serialized before the field existed lack it entirely.
    let mut old_json = serde_json::to_value(&changeset).unwrap();
    old_json
        .as_object_mut()
        .unwrap()
        .remove("single_use_descriptor")
        .unwrap();
    let old_changeset = serde_json::from_value::<ChangeSet>(old_json).unwrap();
    let expected = ChangeSet {
        single_use_descriptor: None,
        ..changeset
    };
    assert_eq!(old_changeset, expected);
}

#[test]
fn changeset_merge_sets_single_use_descriptor() {
    let mut wallet = three_keychain_wallet();
    let changeset = wallet.take_staged().unwrap();
    let only_single_use = ChangeSet {
        single_use_descriptor: changeset.single_use_descriptor.clone(),
        ..Default::default()
    };
    assert!(!only_single_use.is_empty());

    let mut merged = ChangeSet {
        single_use_descriptor: None,
        ..changeset.clone()
    };
    merged.merge(only_single_use);
    assert_eq!(merged, changeset);
}

#[test]
fn load_checks_single_use_descriptor() {
    let mut wallet = three_keychain_wallet();
    wallet.reveal_next_address(KeychainKind::SingleUse);
    let changeset = wallet.take_staged().unwrap();
    let no_single_use = None::<Bip84<Xpriv>>;

    // Matching descriptor loads with its signers.
    let loaded = Wallet::load()
        .descriptor(
            KeychainKind::SingleUse,
            Some(bip84(KeychainKind::SingleUse)),
        )
        .extract_keys()
        .load_wallet_no_persist(changeset.clone())
        .unwrap()
        .unwrap();
    assert_eq!(
        loaded.public_descriptor(KeychainKind::SingleUse),
        wallet.public_descriptor(KeychainKind::SingleUse),
    );
    assert!(!loaded.get_signers(KeychainKind::SingleUse).ids().is_empty());
    assert_eq!(loaded.derivation_index(KeychainKind::SingleUse), Some(0));

    // Mismatched descriptor errors.
    let err = Wallet::load()
        .descriptor(
            KeychainKind::SingleUse,
            Some(Bip86(xprv(), KeychainKind::SingleUse)),
        )
        .load_wallet_no_persist(changeset.clone());
    assert_matches!(
        err,
        Err(LoadError::Mismatch(LoadMismatch::Descriptor {
            keychain: KeychainKind::SingleUse,
            loaded: Some(_),
            expected: Some(_),
        }))
    );

    // Expecting no descriptor errors.
    let err = Wallet::load()
        .descriptor(KeychainKind::SingleUse, no_single_use.clone())
        .load_wallet_no_persist(changeset);
    assert_matches!(
        err,
        Err(LoadError::Mismatch(LoadMismatch::Descriptor {
            keychain: KeychainKind::SingleUse,
            loaded: Some(_),
            expected: None,
        }))
    );

    // A wallet without the keychain loads when expecting none...
    let changeset = Wallet::create(bip84(KeychainKind::External), bip84(KeychainKind::Internal))
        .network(Network::Regtest)
        .create_wallet_no_persist()
        .unwrap()
        .take_staged()
        .unwrap();
    assert!(changeset.single_use_descriptor.is_none());
    let mut loaded = Wallet::load()
        .descriptor(KeychainKind::SingleUse, no_single_use)
        .load_wallet_no_persist(changeset.clone())
        .unwrap()
        .unwrap();
    assert!(loaded
        .keychains()
        .all(|(k, _)| k != KeychainKind::SingleUse));
    assert!(loaded.get_signers(KeychainKind::SingleUse).ids().is_empty());
    // The absent single-use keychain maps to external.
    let addr = loaded.reveal_next_address(KeychainKind::SingleUse);
    assert_eq!(addr.keychain, KeychainKind::External);

    // ...but errors when expecting one.
    let err = Wallet::load()
        .descriptor(
            KeychainKind::SingleUse,
            Some(bip84(KeychainKind::SingleUse)),
        )
        .load_wallet_no_persist(changeset);
    assert_matches!(
        err,
        Err(LoadError::Mismatch(LoadMismatch::Descriptor {
            keychain: KeychainKind::SingleUse,
            loaded: None,
            expected: Some(_),
        }))
    );
}

#[test]
fn export_rejects_single_use_wallet() {
    let wallet = three_keychain_wallet();
    assert!(FullyNodedExport::export_wallet(&wallet, "label", false).is_err());
}
