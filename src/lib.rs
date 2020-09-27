// Rust Elements Library
// Written in 2018 by
//   Andrew Poelstra <apoelstra@blockstream.com>
//
// To the extent possible under law, the author(s) have dedicated all
// copyright and related and neighboring rights to this software to
// the public domain worldwide. This software is distributed without
// any warranty.
//
// You should have received a copy of the CC0 Public Domain Dedication
// along with this software.
// If not, see <http://creativecommons.org/publicdomain/zero/1.0/>.
//

//! # Rust Elements Library
//!
//! Extensions to `rust-bitcoin` to support deserialization and serialization
//! of Elements transactions and blocks.
//!

// Coding conventions
#![deny(non_upper_case_globals)]
#![deny(non_camel_case_types)]
#![deny(non_snake_case)]
#![deny(unused_mut)]
#![deny(missing_docs)]

pub extern crate bitcoin;
#[macro_use]
pub extern crate bitcoin_hashes;
extern crate slip21;
#[cfg(feature = "serde")] extern crate serde;

#[cfg(test)] extern crate rand;
#[cfg(any(test, feature = "serde_json"))] extern crate serde_json;

#[macro_use] mod internal_macros;
pub mod address;
pub mod blech32;
mod block;
pub mod bip143;
pub mod confidential;
pub mod dynafed;
pub mod encode;
mod fast_merkle_root;
pub mod issuance;
mod transaction;
pub mod slip77;

mod interpreter;

// export everything at the top level so it can be used as `elements::Transaction` etc.
pub use address::{Address, AddressParams, AddressError};
pub use transaction::{OutPoint, PeginData, PegoutData, TxIn, TxOut, TxInWitness, TxOutWitness, Transaction, AssetIssuance};
pub use block::{BlockHeader, Block};
pub use block::ExtData as BlockExtData;
pub use ::bitcoin::consensus::encode::VarInt;
pub use fast_merkle_root::fast_merkle_root;
pub use issuance::{AssetId, ContractHash};

#[cfg(test)]
mod tests{

    use bitcoin::Script;
    use bitcoin::blockdata::opcodes::all::*;
    use crate::bitcoin_hashes::Hash;
    use bitcoin::SigHash;
    use crate::encode::{serialize, serialize_hex};
    use super::confidential;
    use super::issuance::AssetId;
    use bip143::{self, SigHashCache};
    use bitcoin_hashes::sha256::Midstate;
    use bitcoin_hashes::hash160;
    use encode::Encodable;
    use bitcoin::WScriptHash;
    use bitcoin::blockdata::script::Builder;
    use super::{Transaction, TxIn, OutPoint, AssetIssuance, TxInWitness, TxOut, TxOutWitness};

    use transaction::SigHashType;
    use super::*;

    fn append_script(a: Script, b: Script) -> Script{
        let x = [a.to_bytes(), b.to_bytes()].concat();
        Script::from(x)
    }
    #[derive(Debug)]
    pub struct ElementsUtxo{
        script_pubkey: bitcoin::Script,
        asset: confidential::Asset,
        value: confidential::Value,
    }

    fn create_tx(_num_inputs: usize, _num_outputs: usize) -> Transaction{
              /*
        rawTransaction testTx1 = (rawTransaction)
          { .input = (rawInput[])
                     { { .prevTxid = (unsigned char[32]){"\xeb\x04\xb6\x8e\x9a\x26\xd1\x16\x04\x6c\x76\xe8\xff\x47\x33\x2f\xb7\x1d\xda\x90\xff\x4b\xef\x53\x70\xf2\x52\x26\xd3\xbc\x09\xfc"}
                       , .prevIx = 0
                       , .sequence = 0xfffffffe
                       , .isPegin = false
                       , .issuance = {0}
                       , .txo = { .asset = (unsigned char[33]){"\x01\x23\x0f\x4f\x5d\x4b\x7c\x6f\xa8\x45\x80\x6e\xe4\xf6\x77\x13\x45\x9e\x1b\x69\xe8\xe6\x0f\xce\xe2\xe4\x94\x0c\x7a\x0d\x5d\xe1\xb2"}
                                , .value = (unsigned char[9]){"\x01\x00\x00\x00\x02\x54\x0b\xe4\x00"}
                                , .scriptPubKey = {0}
                     } }        }
          , .output = (rawOutput[])
                      { { .asset = (unsigned char[33]){"\x01\x23\x0f\x4f\x5d\x4b\x7c\x6f\xa8\x45\x80\x6e\xe4\xf6\x77\x13\x45\x9e\x1b\x69\xe8\xe6\x0f\xce\xe2\xe4\x94\x0c\x7a\x0d\x5d\xe1\xb2"}
                        , .value = (unsigned char[9]){"\x01\x00\x00\x00\x02\x54\x0b\xd7\x1c"}
                        , .nonce = NULL
                        , .scriptPubKey = { .code = (unsigned char [26]){"\x19\x76\xa9\x14\x48\x63\x3e\x2c\x0e\xe9\x49\x5d\xd3\xf9\xc4\x37\x32\xc4\x7f\x47\x02\xa3\x62\xc8\x88\xac"}
                                          , .len = 26
                                          }
                        }
                      , { .asset = (unsigned char[33]){"\x01\x23\x0f\x4f\x5d\x4b\x7c\x6f\xa8\x45\x80\x6e\xe4\xf6\x77\x13\x45\x9e\x1b\x69\xe8\xe6\x0f\xce\xe2\xe4\x94\x0c\x7a\x0d\x5d\xe1\xb2"}
                        , .value = (unsigned char[9]){"\x01\x00\x00\x00\x00\x00\x00\x0c\xe4"}
                        , .nonce = NULL
                        , .scriptPubKey = {0}
                      } }
          , .numInputs = 1
          , .numOutputs = 2
          , .version = 0x00000002
          , .lockTime = 0x00000000
          };
        */
        let asset: [u8; 32] = [
            0x23, 0x0f, 0x4f, 0x5d, 0x4b, 0x7c, 0x6f, 0xa8, 0x45, 0x80, 0x6e, 0xe4, 0xf6, 0x77,
            0x13, 0x45, 0x9e, 0x1b, 0x69, 0xe8, 0xe6, 0x0f, 0xce, 0xe2, 0xe4, 0x94, 0x0c, 0x7a,
            0x0d, 0x5d, 0xe1, 0xb2,
        ];
        let tx_id: [u8; 32] = [
            0xeb, 0x04, 0xb6, 0x8e, 0x9a, 0x26, 0xd1, 0x16, 0x04, 0x6c, 0x76, 0xe8, 0xff, 0x47,
            0x33, 0x2f, 0xb7, 0x1d, 0xda, 0x90, 0xff, 0x4b, 0xef, 0x53, 0x70, 0xf2, 0x52, 0x26,
            0xd3, 0xbc, 0x09, 0xfc,
        ];
        let asset = confidential::Asset::Explicit(AssetId::from_inner(Midstate(asset)));
        //create the txenv
        let elements_tx = Transaction {
            version: 2,
            lock_time: 0,
            input: vec![TxIn {
                previous_output: OutPoint {
                    txid: bitcoin::Txid::from_inner(tx_id),
                    vout: 0,
                },
                sequence: 0xfffffffe,
                is_pegin: false,
                has_issuance: false,
                // perhaps make this an option in elements upstream?
                asset_issuance: AssetIssuance {
                    asset_blinding_nonce: [0; 32],
                    asset_entropy: [0; 32],
                    amount: confidential::Value::Null,
                    inflation_keys: confidential::Value::Null,
                },
                script_sig: Script::new(),
                witness: TxInWitness {
                    amount_rangeproof: vec![],
                    inflation_keys_rangeproof: vec![],
                    script_witness: vec![],
                    pegin_witness: vec![],
                },
            }],
            output: vec![
                TxOut {
                    asset: asset.clone(),
                    value: confidential::Value::Explicit(0x00000002540bd71c),
                    nonce: confidential::Nonce::Null,
                    script_pubkey: hex_script(
                        &"1976a91448633e2c0ee9495dd3f9c43732c47f4702a362c888ac",
                    ),
                    witness: TxOutWitness {
                        surjection_proof: vec![],
                        rangeproof: vec![],
                    },
                },
            ],
        };
        let utxo =  ElementsUtxo{
            script_pubkey: bitcoin::Script::new(),
            asset: asset,
            value: confidential::Value::Explicit(0x00000002540be400),
        };

        elements_tx
    }

    /// Calculate the sighash for elements transaction
    pub fn sighash_message(tx: &Transaction) -> Vec<u8>{
        let mut ret = vec![];
        ret.extend(serialize(&tx.version));
        ret
    }

    fn hex_script(s: &str) -> bitcoin::Script {
        let v: Vec<u8> = bitcoin::hashes::hex::FromHex::from_hex(s).unwrap();
        bitcoin::Script::from(v)
    }

    // Assuming the top of stack as `s`, returns 
    // `s` `s s[start: start + size]`
    fn op_substr(start: i64, size: i64){
        let builder = Builder::new();
        builder.push_opcode(OP_DUP)
        .push_int(start).push_int(size)
        .push_opcode(OP_SUBSTR).into_script();
    }

    // Assuming the top of stack as `s`, returns 
    // `s` `s s[start: start + size]`
    fn op_right(size: i64){
        let builder = Builder::new();
        builder.push_int(size)
        .push_opcode(OP_RIGHT).into_script();
    }

    // Inttial:
    // Stack [witnes pk2.. 1/0 pre post]
    // Alt-stack [hashoutputs sha256(script_pk1)]
    //
    // Final:
    // Stack [witness.. pre post]
    // Alt-stack [hashoutputs sha256(script_pk1) sha256(pk2)]
    fn process_pk(builder: Builder) -> Builder{
        builder.push_opcode(OP_2SWAP)
        .push_opcode(OP_IF)
            .push_opcode(OP_3DUP).push_opcode(OP_SWAP).push_opcode(OP_CAT).push_opcode(OP_CAT)
            .push_opcode(OP_SHA256).push_opcode(OP_TOALTSTACK).push_opcode(OP_DROP)
        .push_opcode(OP_ELSE)
            .push_opcode(OP_2DROP)
        .push_opcode(OP_ENDIF)
    }

    // Assert the size of the second to top element and then cat it
    fn checksize_cat(builder : Builder, size: i64) -> Builder{
        builder.push_opcode(OP_SWAP).push_opcode(OP_SIZE).push_int(size).push_opcode(OP_EQUALVERIFY).push_opcode(OP_CAT)
    }

    // Assert the second to top elem and cat it
    fn checkelem_cat(builder : Builder, elem: &[u8]) -> Builder{
        builder.push_opcode(OP_SWAP).push_opcode(OP_DUP).push_slice(elem).push_opcode(OP_EQUALVERIFY).push_opcode(OP_CAT)
    }

    // Construct an output from individual elements
    // assumes the stack structure as:
    // [script_pk, nonce, value, asset, acc]
    // Returns the stack as 
    // [{acc + asset + value + nonce + script_pk}] as a single elem
    fn process_output(builder: Builder, asset: &[u8]) -> Builder{
        let builder= builder.push_opcode(OP_SWAP)
        .push_opcode(OP_SIZE).push_int(32).push_opcode(OP_EQUALVERIFY) // check size
        .push_int(1).push_opcode(OP_SWAP).push_opcode(OP_CAT)// add explicit prefix
        .push_opcode(OP_DUP)
        .push_slice(asset).push_opcode(OP_EQUAL).push_opcode(OP_TOALTSTACK) // is_covenant_output? pushed to altstack
        .push_opcode(OP_CAT).push_opcode(OP_SWAP);

        builder.push_opcode(OP_SIZE).push_int(8).push_opcode(OP_EQUALVERIFY) // check size of value
        .push_opcode(OP_DUP)
        .push_int(1).push_opcode(OP_SWAP).push_opcode(OP_CAT)
        .push_slice(&[0u8, 33u8, 0u8]).push_opcode(OP_CAT)
        .push_opcode(OP_FROMALTSTACK)
        .push_opcode(OP_IF)
            .push_opcode(OP_FROMALTSTACK)
            .push_opcode(OP_CAT)
            .push_opcode(OP_NIP)//drop the value for now
        .push_opcode(OP_ELSE)
            .push_opcode(OP_NIP).push_opcode(OP_ROT)
            .push_opcode(OP_SIZE).push_int(32).push_opcode(OP_EQUALVERIFY)
            .push_opcode(OP_CAT)
        .push_opcode(OP_ENDIF)
        .push_opcode(OP_CAT)

        //Value is built on the stack
        // .push_opcode(OP_SWAP)

        // .push_opcode(OP_IF)
        //     .push_opcode(OP_DUP).push_opcode(OP_TOALTSTACK)
        //     .push_int(1).push_opcode(OP_SWAP)
        // .push_opcode(OP_ENDIF)
        // .push_int(1).push_opcode(OP_SWAP).push_opcode(OP_CAT)
        // .push_opcode(OP_CAT).push_opcode(OP_SWAP)
        // .push_int(33)
    }

    fn hash_verify(builder: Builder, h: [u8; 20]) -> Builder{
        builder
        .push_opcode(OP_HASH160)
        .push_slice(&h)
        .push_opcode(OP_EQUALVERIFY)
    }
    // Given a script before OP_CODESEP, construct the script after it
    // Assumes the stack structure as 
    // [sig sighash pk pre]
    // We have verified all the covenant logic. Now we only need to verify
    // the sighash was constructed correctly.
    fn post_code_sep(builder : Builder, h: [u8; 20]) -> Builder{
        let builder = hash_verify(builder, h);

        // Post script
        let builder = builder.push_int(2).push_opcode(OP_PICK).push_int(1).push_opcode(OP_CAT).push_opcode(OP_OVER)
        .push_opcode(OP_CHECKSIGVERIFY)
        .push_opcode(OP_SWAP).push_opcode(OP_SHA256).push_opcode(OP_SWAP)
        .push_opcode(OP_CHECKSIGFROMSTACK);
        builder
    }

    fn pre_code_sep() -> Builder{
        let builder = Builder::new();
        builder.push_int(2).push_opcode(OP_PICK).push_opcode(OP_DROP)
        .push_opcode(OP_CODESEPARATOR)
    }

    fn get_covenant_script(pk: bitcoin::PublicKey, asset: confidential::Asset, collector_pk: Script) -> Script{
//
        let scriptpk_len = 395;//Change this
        // Create a covenant that captures value
        // Create a pre-script
        let builder = pre_code_sep();
        let h = hash160::Hash::hash(&builder.clone().into_script().as_bytes());
        let script = post_code_sep(builder, h.into_inner()).into_script();
        script
        // Find the pos of code_sep
        

        // // The sighash is now verified; now check all the fields in the transaction
        // // First get the script_pubkey onto the stack
        // let script_pubkey_start = 4 + 32 + 32 + 32 + 36 + 3;// The last 3 is for the size of len(script)
        // let post_start_index = 3 + 33;
        // let mut builder = builder.push_int(script_pubkey_start).push_opcode(OP_RIGHT)
        // .push_opcode(OP_DUP).push_opcode(OP_2DUP).push_opcode(OP_3DUP) 
        
        // // stack [witness.. scriptpk_*6]
        // // scriptpk_ denotes starting from scriptpk till the end of sighash
        // // Alt stack [None]
        // .push_int(scriptpk_len + 4 + 9).push_int(32).push_opcode(OP_SUBSTR)
        // .push_opcode(OP_TOALTSTACK)

        // // Stack [witnes... scriptpk_*5]
        // // Alt-stack [hashoutputs]
        // .push_int(scriptpk_len).push_opcode(OP_LEFT)
        // .push_opcode(OP_SHA256).push_opcode(OP_TOALTSTACK) 
        
        // // Stack [witnes... scriptpk_*4]
        // // Alt-stack [hashoutputs sha256(script_pubkey)]
        // .push_int(post_start_index).push_int(scriptpk_len - post_start_index)
        // .push_opcode(OP_SUBSTR).push_opcode(OP_TOALTSTACK)
        // // Stack [witnes... scriptpk_*3]
        // // Alt-stack [hashoutputs sha256(script_pubkey) post]
        // .push_int(3).push_opcode(OP_LEFT)
        // .push_opcode(OP_SWAP)
        // // Stack [witnes... script_pk_*2]
        // // Alt-stack [hashoutputs sha256(script_pubkey) post pre]
        // // Check input explicit???
        // .push_int(scriptpk_len).push_int(1).push_opcode(OP_SUBSTR)
        // .push_int(1).push_opcode(OP_EQUALVERIFY).push_opcode(OP_DROP)
        
        // // Stack [witnes... script_pk_]
        // // Alt-stack [hashoutputs sha256(script_pubkey) post pre]
        // // Check total size???
        // .push_opcode(OP_SIZE).push_int(scriptpk_len + 9 + 4 + 32 + 4 + 4)
        // .push_opcode(OP_EQUALVERIFY).push_opcode(OP_DROP)

        // // Stack [witnes...]
        // // Alt-stack [hashoutputs sha256(script_pubkey) post pre]
        // .push_opcode(OP_FROMALTSTACK).push_opcode(OP_FROMALTSTACK);

        // // Stack [witnes... pre post]
        // // Alt-stack [hashoutputs sha256(script_pubkey)]
        // // Process atmost `k` keys
        // let num_cov_outs = 2;
        // for _ in 0..num_cov_outs{
        //     builder = process_pk(builder)
        // }

        // // Stack [witness]
        // // Alt-stack [hashoutputs sha256(script_pubkey) sha256(pk1) sha256(pk2) sha256(pk3)]
        // // Process the outputs. Index 0 must be covenant fee output

        // // TODO: Change this
        // let builder = builder.push_opcode(OP_PUSHBYTES_0);// accumulator for TxOutput
        // let builder = checkelem_cat(builder, &serialize(&asset));
        // let builder = checksize_cat(builder, 9);

        // let mut remain_bytes = vec![0u8];
        
        // assert!(collector_pk.is_v0_p2wsh());
        // remain_bytes.extend(&collector_pk.to_bytes());
        // let mut builder = checkelem_cat(builder, &remain_bytes);

        // // Check the other outputs
        // let max_outputs = 2;
        // for _ in 0..max_outputs{
        //     builder = process_output(builder, &serialize(&asset));
        // }

        // // If not having any change output. Allow the user to drop from alt stack
        // let builder = builder.push_opcode(OP_IF)
        //     .push_opcode(OP_FROMALTSTACK)
        //     .push_opcode(OP_DROP)
        // .push_opcode(OP_ENDIF);

        // // Get the last fee output
        // // Note we only check whether this has the correct size.
        // // None of the previous could have been fee output as they were forced
        // // to be p2wsh. 
        // let builder = checkelem_cat(builder, &serialize(&asset));
        // let builder = checksize_cat(builder, 9 + 1 + 1);
        // // Now calculate the hashoutput and match it
        // let builder = 
        //     builder.push_opcode(OP_HASH256).push_opcode(OP_FROMALTSTACK).push_opcode(OP_EQUALVERIFY);
        // let script_pubkey = builder.into_script();
        // assert_eq!(scriptpk_len as usize, script_pubkey.len());
        // script_pubkey
    }
    #[test]
    fn simple_covenant(){
        let asset: [u8; 32] = [
            0x23, 0x0f, 0x4f, 0x5d, 0x4b, 0x7c, 0x6f, 0xa8, 0x45, 0x80, 0x6e, 0xe4, 0xf6, 0x77,
            0x13, 0x45, 0x9e, 0x1b, 0x69, 0xe8, 0xe6, 0x0f, 0xce, 0xe2, 0xe4, 0x94, 0x0c, 0x7a,
            0x0d, 0x5d, 0xe1, 0xb2,
        ];
        let asset = confidential::Asset::Explicit(AssetId::from_inner(Midstate(asset)));

        let mut tx = create_tx(0, 0);
        use std::str::FromStr;
        use bitcoin::secp256k1::Secp256k1;
        let test_pk = bitcoin::PublicKey::from_str("02a05cab7cf0e66e6684b22c15fa524ffcff8913a9088780ecccc3e7b10baaaa81").unwrap();
        let test_priv_key = bitcoin::PrivateKey::from_wif("cVGQewjMcqa5PBvSvid8XeqoKA66YsVf6U9EkbgR4HFhU6DHsrEg").unwrap();

        let secp = Secp256k1::new();
        assert!(test_pk == test_priv_key.public_key(&secp));
        
        // Create a legit script here
        let tmp = Script::new();

        let script_pubkey = get_covenant_script(test_pk, asset, tmp.to_v0_p2wsh());
        println!("{}", &script_pubkey);
        tx.output[0].script_pubkey = script_pubkey.to_v0_p2wsh();

        println!("{}", address::Address::p2wsh(&script_pubkey, None, &AddressParams::ELEMENTS));
        println!("{}", serialize_hex(&tx));

        // Now create a transaction spending this.
        let mut spend_tx = Transaction {
            version: 2,
            lock_time: 0,
            input: vec![TxIn {
                previous_output: OutPoint {
                    txid: bitcoin::Txid::from_str("e79659cb4925cd88cfa722c907c9828cd476c5b1e6d3c71a92a727c79e49d08e").unwrap(),
                    vout: 1,
                },
                sequence: 0xfffffffe,
                is_pegin: false,
                has_issuance: false,
                // perhaps make this an option in elements upstream?
                asset_issuance: AssetIssuance {
                    asset_blinding_nonce: [0; 32],
                    asset_entropy: [0; 32],
                    amount: confidential::Value::Null,
                    inflation_keys: confidential::Value::Null,
                },
                script_sig: Script::new(),
                witness: TxInWitness {
                    amount_rangeproof: vec![],
                    inflation_keys_rangeproof: vec![],
                    script_witness: vec![],
                    pegin_witness: vec![],
                },
            }],
            output: vec![
                TxOut {
                    asset: asset.clone(),
                    value: confidential::Value::Explicit(1000000),
                    nonce: confidential::Nonce::Null,
                    script_pubkey: tmp.to_v0_p2wsh(),
                    witness: TxOutWitness {
                        surjection_proof: vec![],
                        rangeproof: vec![],
                    },
                },
                TxOut {
                    asset: asset.clone(),
                    value: confidential::Value::Explicit(98000000),
                    nonce: confidential::Nonce::Null,
                    script_pubkey: script_pubkey.to_v0_p2wsh(),
                    witness: TxOutWitness {
                        surjection_proof: vec![],
                        rangeproof: vec![],
                    },
                },
                TxOut {
                    asset: asset.clone(),
                    value: confidential::Value::Explicit(1000000),
                    nonce: confidential::Nonce::Null,
                    script_pubkey: Script::new(),
                    witness: TxOutWitness {
                        surjection_proof: vec![],
                        rangeproof: vec![],
                    },
                },
            ],
        };


        let pre_code = pre_code_sep().into_script().into_bytes();
        let script_code = 
        post_code_sep(Builder::new(), hash160::Hash::hash(&pre_code).into_inner()).into_script();
        let mut cache = SigHashCache::new(&spend_tx);
        let sighash_type = SigHashType::from_u32(1);
        let actual_result = cache.signature_hash(0, &script_code, confidential::Value::Explicit(0x0000000005f5e100), sighash_type);
        // let mut enc = SigHash::engine();
        println!("{:x?}", &actual_result);
        let mut ser_out = vec![];
        for tx_out in &spend_tx.output{
            ser_out.extend(serialize(tx_out));
        }
        println!("{:x?}", ser_out);
        println!("{:x?}", serialize(&spend_tx.output[0].script_pubkey));
        assert_eq!(actual_result[8], SigHash::hash(&ser_out).into_inner());
        let sighash_msg : Vec<u8> = actual_result.into_iter().flatten().collect();
        let mut eng = SigHash::engine();
        use bitcoin_hashes::HashEngine;
        eng.input(&sighash_msg);
        let sighash_u256 = SigHash::from_engine(eng);

        println!("{} Msg here", sighash_u256);
        let sig = secp.sign( &bitcoin::secp256k1::Message::from_slice(&sighash_u256[..]).unwrap(), &test_priv_key.key);
        let ser_sig = Vec::from(sig.serialize_der().as_ref());
        
        // ser_sig.push(1u8); // sighash all
        println!("Msg len: {}", sighash_msg.len());
        let mut stk = vec![ser_sig, sighash_msg, test_pk.to_bytes(), pre_code];

        // let mut interp = interpreter::State::init_witness(stk.clone());
        // interp.execute_script(script_pubkey.clone());

        stk.push(script_pubkey.clone().into_bytes());
        spend_tx.input[0].witness.script_witness = stk;
        println!("{}", serialize_hex(&spend_tx));
    }
}
