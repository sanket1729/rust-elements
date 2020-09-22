// Rust Bitcoin Library
// Written in 2018 by
//     Andrew Poelstra <apoelstra@wpsoftware.net>
// To the extent possible under law, the author(s) have dedicated all
// copyright and related and neighboring rights to this software to
// the public domain worldwide. This software is distributed without
// any warranty.
//
// You should have received a copy of the CC0 Public Domain Dedication
// along with this software.
// If not, see <http://creativecommons.org/publicdomain/zero/1.0/>.
//

//! BIP143 Implementation
//!
//! Implementation of BIP143 Segwit-style signatures. Should be sufficient
//! to create signatures for Segwit transactions (which should be pushed into
//! the appropriate place in the `Transaction::witness` array) or bcash
//! signatures, which are placed in the scriptSig.
//!

use bitcoin::hashes::{Hash, sha256d};
use bitcoin::hash_types::SigHash;
use bitcoin::blockdata::script::Script;
use transaction::Transaction;
use encode::Encodable;
use transaction::SigHashType;
use std::ops::{Deref, DerefMut};
use encode::serialize;


/// A replacement for SigHashComponents which supports all sighash modes
pub struct SigHashCache<R: Deref<Target=Transaction>> {
    /// Access to transaction required for various introspection
    tx: R,
    /// Hash of all the previous outputs, computed as required
    hash_prevouts: Option<sha256d::Hash>,
    /// Hash of all the input sequence nos, computed as required
    hash_sequence: Option<sha256d::Hash>,
    /// Hash of all the outputs in this transaction, computed as required
    hash_outputs: Option<sha256d::Hash>,
    /// Hash of all the issunaces in this transaction, computed as required
    hash_issuances: Option<sha256d::Hash>,
}

impl<R: Deref<Target=Transaction>> SigHashCache<R> {
    /// Compute the sighash components from an unsigned transaction and auxiliary
    /// in a lazy manner when required.
    /// For the generated sighashes to be valid, no fields in the transaction may change except for
    /// script_sig and witnesses.
    pub fn new(tx: R) -> Self {
        SigHashCache {
            tx: tx,
            hash_prevouts: None,
            hash_sequence: None,
            hash_outputs: None,
            hash_issuances: None,
        }
    }

    /// Calculate hash for prevouts
    pub fn hash_prevouts(&mut self) -> sha256d::Hash {
        let hash_prevout = &mut self.hash_prevouts;
        let input = &self.tx.input;
        *hash_prevout.get_or_insert_with(|| {
            let mut enc = sha256d::Hash::engine();
            for txin in input {
                txin.previous_output.consensus_encode(&mut enc).unwrap();
            }
            sha256d::Hash::from_engine(enc)
        })
    }

    /// Calculate hash for input sequence values
    pub fn hash_sequence(&mut self) -> sha256d::Hash {
        let hash_sequence = &mut self.hash_sequence;
        let input = &self.tx.input;
        *hash_sequence.get_or_insert_with(|| {
            let mut enc = sha256d::Hash::engine();
            for txin in input {
                txin.sequence.consensus_encode(&mut enc).unwrap();
            }
            sha256d::Hash::from_engine(enc)
        })
    }

    /// Calculate hash for outputs
    pub fn hash_issuances(&mut self) -> sha256d::Hash {
        let hash_issuance = &mut self.hash_issuances;
        let input = &self.tx.input;
        *hash_issuance.get_or_insert_with(|| {
            let mut enc = sha256d::Hash::engine();
            for txin in input {
                if txin.has_issuance() {
                    txin.asset_issuance.consensus_encode(&mut enc).unwrap();
                    unreachable!();// temp assertion
                } else {
                    0u8.consensus_encode(&mut enc).unwrap();
                }
            }
            sha256d::Hash::from_engine(enc)
        })
    }

    /// Calculate hash for outputs
    pub fn hash_outputs(&mut self) -> sha256d::Hash {
        let hash_output = &mut self.hash_outputs;
        let output = &self.tx.output;
        *hash_output.get_or_insert_with(|| {
            let mut enc = sha256d::Hash::engine();
            for txout in output {
                txout.consensus_encode(&mut enc).unwrap();
            }
            sha256d::Hash::from_engine(enc)
        })
    }

    /// Compute the BIP143 sighash for any flag type. See SighashComponents::sighash_all simpler
    /// API for the most common case
    pub fn signature_hash(&mut self, input_index: usize, script_code: &Script, value: crate::confidential::Value, sighash_type: SigHashType) -> Vec<Vec<u8>> {

        let zero_hash = sha256d::Hash::default();

        let (sighash, anyone_can_pay) = sighash_type.split_anyonecanpay_flag();

        let mut enc = SigHash::engine();
        let mut ret = vec![];
        ret.push(serialize(&self.tx.version));

        if !anyone_can_pay {
            ret.push(serialize(&self.hash_prevouts()));
        } else {
            ret.push(serialize(&zero_hash));
        }

        if !anyone_can_pay && sighash != SigHashType::Single && sighash != SigHashType::None {
            ret.push(serialize(&self.hash_sequence()));
        } else {
            ret.push(serialize(&zero_hash));
        }

        // elements mode. Push the hash issuance zero hash as required 
        // If required implement for issuance, but not necessary as of now
        {
            if !anyone_can_pay {
                ret.push(serialize(&self.hash_issuances()));
            } else {
                ret.push(serialize(&zero_hash));
            }
        }
        {
            let txin = &self.tx.input[input_index];

            ret.push(serialize(&txin.previous_output));
            ret.push(serialize(script_code));
            ret.push(serialize(&value));
            ret.push(serialize(&txin.sequence));
        }

        if sighash != SigHashType::Single && sighash != SigHashType::None {
            ret.push(serialize(&self.hash_outputs()));
        } else if sighash == SigHashType::Single && input_index < self.tx.output.len() {
            // let mut single_enc = SigHash::engine();
            // self.tx.output[input_index].consensus_encode(&mut single_enc).unwrap();
            // use bitcoin::consensus::Encodable;
            // SigHash::from_engine(single_enc).consensus_encode(&mut enc).unwrap();
            unimplemented!();
        } else {
            zero_hash.consensus_encode(&mut enc).unwrap();
            ret.push(serialize(&zero_hash));
        }

        ret.push(serialize(&self.tx.lock_time));
        ret.push(serialize(&sighash_type.as_u32()));
        ret
    }
}


#[cfg(test)]
#[allow(deprecated)]
mod tests {
    use bitcoin::blockdata::script::Script;
    use encode::deserialize;
    use bitcoin::hashes::hex::FromHex;

    use super::*;


    // fn run_test_sighash_bip143(tx: &str, script: &str, input_index: usize, value: u64, hash_type: u32, expected_result: &str) {
    //     let tx: Transaction = deserialize(&Vec::<u8>::from_hex(tx).unwrap()[..]).unwrap();
    //     let script = Script::from(Vec::<u8>::from_hex(script).unwrap());
    //     let raw_expected = SigHash::from_hex(expected_result).unwrap();
    //     let expected_result = SigHash::from_slice(&raw_expected[..]).unwrap();
    //     let mut cache = SigHashCache::new(&tx);
    //     let sighash_type = SigHashType::from_u32(hash_type);
    //     let actual_result = cache.signature_hash(input_index, &script, value, sighash_type);
    //     let mut enc = SigHash::engine();
    //     let actual_result : Vec<u8> = actual_result.into_iter().flatten().collect();
    //     actual_result.consensus_encode(&mut enc).unwrap();
    //     let actual_result = SigHash::from_engine(enc);
    //     assert_eq!(actual_result, expected_result);
    // }

    // #[test]
    // fn bip143_sighash_flags() {
    //     // All examples generated via Bitcoin Core RPC using signrawtransactionwithwallet
    //     // with additional debug printing
    //     run_test_sighash_bip143("0200000001cf309ee0839b8aaa3fbc84f8bd32e9c6357e99b49bf6a3af90308c68e762f1d70100000000feffffff0288528c61000000001600146e8d9e07c543a309dcdeba8b50a14a991a658c5be0aebb0000000000160014698d8419804a5d5994704d47947889ff7620c004db000000", "76a91462744660c6b5133ddeaacbc57d2dc2d7b14d0b0688ac", 0, 1648888940, 0x01, "0a1bc2758dbb5b3a56646f8cafbf63f410cc62b77a482f8b87552683300a7711");
    //     run_test_sighash_bip143("0200000001cf309ee0839b8aaa3fbc84f8bd32e9c6357e99b49bf6a3af90308c68e762f1d70100000000feffffff0288528c61000000001600146e8d9e07c543a309dcdeba8b50a14a991a658c5be0aebb0000000000160014698d8419804a5d5994704d47947889ff7620c004db000000", "76a91462744660c6b5133ddeaacbc57d2dc2d7b14d0b0688ac", 0, 1648888940, 0x02, "3e275ac8b084f79f756dcd535bffb615cc94a685eefa244d9031eaf22e4cec12");
    //     run_test_sighash_bip143("0200000001cf309ee0839b8aaa3fbc84f8bd32e9c6357e99b49bf6a3af90308c68e762f1d70100000000feffffff0288528c61000000001600146e8d9e07c543a309dcdeba8b50a14a991a658c5be0aebb0000000000160014698d8419804a5d5994704d47947889ff7620c004db000000", "76a91462744660c6b5133ddeaacbc57d2dc2d7b14d0b0688ac", 0, 1648888940, 0x03, "191a08165ffacc3ea55753b225f323c35fd00d9cc0268081a4a501921fc6ec14");
    //     run_test_sighash_bip143("0200000001cf309ee0839b8aaa3fbc84f8bd32e9c6357e99b49bf6a3af90308c68e762f1d70100000000feffffff0288528c61000000001600146e8d9e07c543a309dcdeba8b50a14a991a658c5be0aebb0000000000160014698d8419804a5d5994704d47947889ff7620c004db000000", "76a91462744660c6b5133ddeaacbc57d2dc2d7b14d0b0688ac", 0, 1648888940, 0x81, "4b6b612530f94470bbbdef18f57f2990d56b239f41b8728b9a49dc8121de4559");
    //     run_test_sighash_bip143("0200000001cf309ee0839b8aaa3fbc84f8bd32e9c6357e99b49bf6a3af90308c68e762f1d70100000000feffffff0288528c61000000001600146e8d9e07c543a309dcdeba8b50a14a991a658c5be0aebb0000000000160014698d8419804a5d5994704d47947889ff7620c004db000000", "76a91462744660c6b5133ddeaacbc57d2dc2d7b14d0b0688ac", 0, 1648888940, 0x82, "a7e916d3acd4bb97a21e6793828279aeab02162adf8099ea4f309af81f3d5adb");
    //     run_test_sighash_bip143("0200000001cf309ee0839b8aaa3fbc84f8bd32e9c6357e99b49bf6a3af90308c68e762f1d70100000000feffffff0288528c61000000001600146e8d9e07c543a309dcdeba8b50a14a991a658c5be0aebb0000000000160014698d8419804a5d5994704d47947889ff7620c004db000000", "76a91462744660c6b5133ddeaacbc57d2dc2d7b14d0b0688ac", 0, 1648888940, 0x83, "d9276e2a48648ddb53a4aaa58314fc2b8067c13013e1913ffb67e0988ce82c78");
    // }
}