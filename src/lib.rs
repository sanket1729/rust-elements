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
#[cfg(feature = "serde")]
extern crate serde;
extern crate slip21;

#[cfg(test)]
extern crate rand;
#[cfg(any(test, feature = "serde_json"))]
extern crate serde_json;

#[macro_use]
mod internal_macros;
pub mod address;
pub mod bip143;
pub mod blech32;
mod block;
pub mod confidential;
pub mod dynafed;
pub mod encode;
mod fast_merkle_root;
pub mod hash_types;
pub mod issuance;
pub mod opcodes;
pub mod script;
pub mod slip77;
mod transaction;

#[cfg(test)]
mod interpreter;

// export everything at the top level so it can be used as `elements::Transaction` etc.
pub use address::{Address, AddressError, AddressParams};
pub use bitcoin::consensus::encode::VarInt;
pub use block::ExtData as BlockExtData;
pub use block::{Block, BlockHeader};
pub use fast_merkle_root::fast_merkle_root;
pub use hash_types::*;
pub use issuance::{AssetId, ContractHash};
pub use script::Script;
pub use transaction::{
    AssetIssuance, OutPoint, PeginData, PegoutData, Transaction, TxIn, TxInWitness, TxOut,
    TxOutWitness,
};

#[cfg(test)]
mod tests {

    use super::confidential;
    use super::issuance::AssetId;
    use super::{AssetIssuance, OutPoint, Transaction, TxIn, TxInWitness, TxOut};
    use crate::bitcoin_hashes::Hash;
    use crate::encode::{serialize, serialize_hex};
    use bip143::SigHashCache;
    use bitcoin::secp256k1::{self, Secp256k1};
    use bitcoin_hashes::{hash160, sha256, sha256::Midstate, HashEngine};
    use opcodes::all::*;
    use script::Builder;
    use std::str::FromStr;
    use Script;
    use SigHash;

    use super::*;
    use transaction::SigHashType;

    const BTC_ASSET: [u8; 32] = [
        0x23, 0x0f, 0x4f, 0x5d, 0x4b, 0x7c, 0x6f, 0xa8, 0x45, 0x80, 0x6e, 0xe4, 0xf6, 0x77, 0x13,
        0x45, 0x9e, 0x1b, 0x69, 0xe8, 0xe6, 0x0f, 0xce, 0xe2, 0xe4, 0x94, 0x0c, 0x7a, 0x0d, 0x5d,
        0xe1, 0xb2,
    ];

    #[derive(Debug, Clone)]
    // All the info required for covenant script creation.
    // Does *NOT* include information for witness script creation
    pub struct CovenantScriptContext {
        pub traded_asset: confidential::Asset,
        pub redeem_pk: bitcoin::PublicKey,
        pub fee_collector_wsh: Script,
        // server pks
        pub fee_collector_srv_pk: bitcoin::PublicKey,
        pub timestamp_srv_pk: bitcoin::PublicKey,
    }

    // Information required for constructing the complete
    // transaction input with witness
    pub struct CovenantTxContext {
        // Transaction skeleton
        // These things are to be constructed after the transaction is
        // constructed as they require sighash, signatures etc..
        pub tx: Transaction,
        pub index: usize,
        // The covenant script context
        pub cov_script_ctx: CovenantScriptContext,
        pub receiver_pk: bitcoin::PublicKey,
        //amts
        pub sent_amt: confidential::Value,
        pub change_amt: confidential::Value,
        pub fee_amt: confidential::Value,
        pub tx_fee_btc: confidential::Value,

        pub redeem_priv_key: bitcoin::PrivateKey,

        // Sigs and msgs
        pub timestamp_srv_msg: Vec<u8>,
        pub timestamp_srv_sig: Vec<u8>,
        pub fee_srv_msg: Vec<u8>,
        pub fee_srv_sig: Vec<u8>,
    }

    // In script element zero is represented as [], whereas in ScriptInt form it
    // is &[00].
    // This function parses the script top as checks whether it is zero
    // and returns 2 elements. [top res]
    // Case 1) if top elements is zero, this returns top 0
    // Case 2) Otherwise this returns x 1
    // fn check_top_zero(builder: Builder) -> Builder {
    //     builder
    //         .push_opcode(OP_DUP)
    //         .push_slice(&[0u8])
    //         .push_opcode(OP_EQUAL)
    //         .push_opcode(OP_IF)
    //         .push_opcode(OP_DROP)
    //         .push_opcode(OP_PUSHBYTES_0)
    //         .push_int(0)
    //         .push_opcode(OP_ELSE)
    //         .push_int(1)
    //         .push_opcode(OP_ENDIF)
    // }

    // fn parse_non_head_bytes(builder: Builder) -> Builder {
    //     let builder = builder
    //         .push_opcode(OP_IF)
    //         .push_opcode(OP_SWAP)
    //         .push_opcode(OP_CAT)
    //         .push_int(1)
    //         .push_opcode(OP_ELSE)
    //         .push_opcode(OP_SWAP);
    //     let builder = check_top_zero(builder);
    //     builder
    //         .push_opcode(OP_TOALTSTACK)
    //         .push_opcode(OP_CAT)
    //         .push_opcode(OP_FROMALTSTACK)
    //         .push_opcode(OP_ENDIF)
    // }

    fn check_elem_zeros(builder: Builder) -> Builder {
        let mut arr = vec![];
        let mut builder2 = builder;
        for i in 0..3 {
            builder2 = builder2
                .push_opcode(OP_DUP)
                .push_slice(&arr)
                .push_opcode(OP_EQUAL)
                .push_opcode(OP_SWAP);
            arr.push(0u8);
        }
        builder2
            .push_slice(&arr)
            .push_opcode(OP_EQUAL)
            .push_opcode(OP_BOOLOR)
            .push_opcode(OP_BOOLOR)
            .push_opcode(OP_BOOLOR)
            .push_opcode(OP_VERIFY)
    }

    // Assuming a 8 byte stack top.
    fn calc_fees(builder: Builder, stk_size: &mut i64) -> Builder {
        let builder = builder
            // .push_opcode(OP_DUP)
            .push_int(*stk_size - 6)
            .push_opcode(OP_ROLL)
            .push_opcode(OP_LSHIFT);
        // .push_opcode(OP_SWAP);

        // let builder = builder
        //     .push_int(*stk_size - 6)
        //     .push_opcode(OP_ROLL)
        //     .push_opcode(OP_LSHIFT);

        builder
    }

    fn convert_to_script_num(
        builder: Builder,
        stk_size: &mut i64,
        zeros_pos1: i64,
        zeros_pos2: i64,
    ) -> Builder {
        // 1) Split the num into parts
        let builder = builder
            .push_opcode(OP_DUP)
            .push_int(4)
            .push_opcode(OP_RIGHT)
            .push_opcode(OP_SWAP)
            .push_int(4)
            .push_opcode(OP_LEFT);

        *stk_size += 1;

        convert_to_script_num_helper(builder, stk_size, zeros_pos1, zeros_pos2)
    }

    fn convert_to_script_num_helper(
        builder: Builder,
        stk_size: &mut i64,
        zeros_pos1: i64,
        zeros_pos2: i64,
    ) -> Builder {
        let builder = builder
            .push_opcode(OP_DUP)
            .push_int(*stk_size + 1 - 6)
            .push_opcode(OP_PICK)
            .push_opcode(OP_RIGHT);
        *stk_size += 1;
        // Now get the required zeros
        let builder = builder
            .push_opcode(OP_SIZE)
            .push_opcode(OP_NEGATE)
            .push_int(zeros_pos1)
            .push_opcode(OP_ADD)
            .push_opcode(OP_PICK)
            .push_opcode(OP_EQUALVERIFY)
            .push_int(*stk_size - 1 - 6)
            .push_opcode(OP_ROLL)
            .push_opcode(OP_LEFT)
            .push_opcode(OP_SWAP);
        *stk_size -= 2;

        //Now the second part
        let builder = builder
            .push_opcode(OP_DUP)
            .push_int(*stk_size + 1 - 6)
            .push_opcode(OP_PICK)
            .push_opcode(OP_RIGHT);
        *stk_size += 1;
        // Now get the required zeros
        let builder = builder
            .push_opcode(OP_SIZE)
            .push_opcode(OP_NEGATE)
            .push_int(zeros_pos2)
            .push_opcode(OP_ADD)
            .push_opcode(OP_PICK)
            .push_opcode(OP_EQUALVERIFY)
            .push_int(*stk_size - 1 - 6)
            .push_opcode(OP_ROLL)
            .push_opcode(OP_LEFT);
        *stk_size -= 2;
        builder
    }

    // assumes the stack contains 4 values on top.
    // [ high_bits_b, low_bits_b, high_bits_a, low_bits_a]
    fn perform_add(builder: Builder, stk_size: &mut i64) -> Builder {
        let builder = builder
            .push_int(2)
            .push_opcode(OP_ROLL)
            .push_opcode(OP_ADD)
            .push_opcode(OP_TOALTSTACK);
        *stk_size -= 2;

        let builder = builder.push_opcode(OP_ADD).push_opcode(OP_FROMALTSTACK);
        *stk_size -= 0;
        //Now this could overflow
        // Deal with this later. Does not in our example

        builder
    }

    // Assumes the following form for the numbers
    // [low_bits_a, high_bits_a, high_bits_b, low_bits_b]
    fn compare_script_nums(builder: Builder, stk_size: &mut i64) -> Builder {
        let builder = builder.push_int(3).push_opcode(OP_ROLL);

        let builder = builder
            .push_opcode(OP_LESSTHANOREQUAL)
            .push_opcode(OP_TOALTSTACK);

        let builder = builder
            .push_opcode(OP_2DUP)
            .push_opcode(OP_EQUAL)
            .push_opcode(OP_TOALTSTACK)
            .push_opcode(OP_GREATERTHAN)
            .push_opcode(OP_FROMALTSTACK)
            .push_opcode(OP_FROMALTSTACK)
            .push_opcode(OP_BOOLAND)
            .push_opcode(OP_BOOLOR)
            .push_opcode(OP_VERIFY);
        *stk_size -= 4;
        builder
    }

    fn convert_sent_amt_to_script_num(
        builder: Builder,
        stk_size: &mut i64,
        start_pos: i64,
    ) -> Builder {
        assert!(*stk_size == 18, format!("{}", *stk_size));
        let mut builder = builder;

        let mut start_pos = start_pos;
        for i in 0..6 {
            builder = builder
                .push_opcode(OP_DUP)
                .push_int(start_pos)
                .push_int(1)
                .push_opcode(OP_SUBSTR)
                .push_opcode(OP_SWAP);
            start_pos = start_pos - 1;
        }
        let builder = builder
            .push_int(start_pos)
            .push_int(1)
            .push_opcode(OP_SUBSTR);

        let builder = builder
            .push_opcode(OP_CAT)
            .push_opcode(OP_CAT)
            .push_opcode(OP_TOALTSTACK)
            .push_opcode(OP_CAT)
            .push_opcode(OP_CAT)
            .push_opcode(OP_CAT)
            .push_opcode(OP_FROMALTSTACK);

        *stk_size += 1;

        convert_to_script_num_helper(builder, stk_size, 10, 10)
    }

    fn convert_amt_three_bytes_to_script_num(
        builder: Builder,
        stk_size: &mut i64,
        start_pos: i64,
    ) -> Builder {
        assert!(*stk_size == 19, format!("{}", *stk_size));
        let mut builder = builder;

        let mut start_pos = start_pos;
        for i in 0..5 {
            builder = builder
                .push_opcode(OP_DUP)
                .push_int(start_pos)
                .push_int(1)
                .push_opcode(OP_SUBSTR)
                .push_opcode(OP_SWAP);
            start_pos = start_pos - 1;
        }
        let builder = builder
            .push_int(start_pos)
            .push_int(1)
            .push_opcode(OP_SUBSTR);

        let builder = builder
            .push_opcode(OP_CAT)
            .push_opcode(OP_CAT)
            .push_opcode(OP_CAT)
            .push_opcode(OP_CAT)
            .push_opcode(OP_CAT);
        // .push_slice(&[0u8])
        // .push_opcode(OP_CAT);
        assert!(*stk_size == 19, format!("{}", *stk_size));
        let builder = calc_fees(builder, stk_size);
        *stk_size -= 1;
        let builder = convert_to_script_num(builder, stk_size, 8, 8);
        // let builder = builder.push_int(2).push_opcode(OP_ROLL);
        // let builder = convert_to_script_num(builder, stk_size, 6, 8);
        builder
        // // Now the three bytes are on top
        // let builder = check_top_zero(builder);
        // // Now the stack either contains
        // // case 1) [] 0
        // // case 2) byte 1
        // let builder = parse_non_head_bytes(builder);
        // parse_non_head_bytes(builder)
    }
    // // convert the top of stack to 3 byte num representation
    // fn convert_script_num_to_repr(builder : Builder) -> Builder{
    //     let builder =
    //         builder.push_opcode(OP_SIZE).push_int(4).push_opcode(OP_EQUAL)
    //             .push_opcode(OP_IF)
    //                 .push_opcode(OP_DUP).push_int(3).push_opcode(OP_RIGHT)
    //                 .push_slice(&[0u8;1]).push_opcode(OP_EQUALVERIFY)
    //             .push_opcode(OP_ENDIF);//change to elseif nested later
    //             // interpretetor does not support nesting yet
    //     let builder =
    //     builder.push_opcode(OP_SIZE).push_int(3).push_opcode(OP_GREATERTHANOREQUAL)
    //         .push_opcode(OP_IF)
    //             .push_opcode(OP_DUP).push_int(2).push_int(1).push_opcode(OP_SUBSTR).push_opcode(OP_SWAP)
    //             .push_opcode(OP_DUP).push_int(1).push_int(1).push_opcode(OP_SUBSTR).push_opcode(OP_SWAP)
    //             .push_int(1).push_opcode(OP_LEFT)
    //             .push_opcode(OP_CAT).push_opcode(OP_CAT)
    //         .push_opcode(OP_ENDIF);//change to elseif nested later

    //     let builder = builder.push_opcode(OP_SIZE).push_int(2).push_opcode(OP_EQUAL)
    //         .push_opcode(OP_IF)
    //             .push_slice(&[0u8;1]).push_opcode(OP_SWAP)
    //             .push_opcode(OP_DUP).push_int(1).push_opcode(OP_RIGHT).push_opcode(OP_SWAP)
    //             .push_int(1).push_opcode(OP_LEFT)
    //             .push_opcode(OP_CAT).push_opcode(OP_CAT)
    //         .push_opcode(OP_ENDIF);

    //     let builder = builder.push_opcode(OP_SIZE).push_int(1).push_opcode(OP_EQUAL)
    //         .push_opcode(OP_IF)
    //             .push_slice(&[0u8;2]).push_opcode(OP_SWAP).push_opcode(OP_CAT)
    //         .push_opcode(OP_ENDIF);

    //     let builder = builder.push_opcode(OP_SIZE).push_int(0).push_opcode(OP_EQUAL)
    //         .push_opcode(OP_IF)
    //             .push_slice(&[0u8;3]).push_opcode(OP_CAT)
    //         .push_opcode(OP_ENDIF);

    //     builder
    // }

    // fn convert_amt_three_bytes_to_script_num(builder : Builder) -> Builder{
    //     let builder = builder
    //         .push_opcode(OP_DUP).push_int(5).push_int(1).push_opcode(OP_SUBSTR).push_opcode(OP_SWAP)
    //         .push_opcode(OP_DUP).push_int(6).push_int(1).push_opcode(OP_SUBSTR).push_opcode(OP_SWAP)
    //         .push_int(7).push_int(1).push_opcode(data)
    //     builder
    // }
    // // convert the top of stack to 3 byte num representation
    // fn convert_script_num_to_repr(builder : Builder) -> Builder{
    //     let builder =
    //         builder.push_opcode(OP_SIZE).push_int(4).push_opcode(OP_EQUAL)
    //             .push_opcode(OP_IF)
    //                 .push_opcode(OP_DUP).push_int(3).push_opcode(OP_RIGHT)
    //                 .push_slice(&[0u8;1]).push_opcode(OP_EQUALVERIFY)
    //             .push_opcode(OP_ENDIF);//change to elseif nested later
    //             // interpretetor does not support nesting yet
    //     let builder =
    //     builder.push_opcode(OP_SIZE).push_int(3).push_opcode(OP_GREATERTHANOREQUAL)
    //         .push_opcode(OP_IF)
    //             .push_opcode(OP_DUP).push_int(2).push_int(1).push_opcode(OP_SUBSTR).push_opcode(OP_SWAP)
    //             .push_opcode(OP_DUP).push_int(1).push_int(1).push_opcode(OP_SUBSTR).push_opcode(OP_SWAP)
    //             .push_int(1).push_opcode(OP_LEFT)
    //             .push_opcode(OP_CAT).push_opcode(OP_CAT)
    //         .push_opcode(OP_ENDIF);//change to elseif nested later

    //     let builder = builder.push_opcode(OP_SIZE).push_int(2).push_opcode(OP_EQUAL)
    //         .push_opcode(OP_IF)
    //             .push_slice(&[0u8;1]).push_opcode(OP_SWAP)
    //             .push_opcode(OP_DUP).push_int(1).push_opcode(OP_RIGHT).push_opcode(OP_SWAP)
    //             .push_int(1).push_opcode(OP_LEFT)
    //             .push_opcode(OP_CAT).push_opcode(OP_CAT)
    //         .push_opcode(OP_ENDIF);

    //     let builder = builder.push_opcode(OP_SIZE).push_int(1).push_opcode(OP_EQUAL)
    //         .push_opcode(OP_IF)
    //             .push_slice(&[0u8;2]).push_opcode(OP_SWAP).push_opcode(OP_CAT)
    //         .push_opcode(OP_ENDIF);

    //     let builder = builder.push_opcode(OP_SIZE).push_int(0).push_opcode(OP_EQUAL)
    //         .push_opcode(OP_IF)
    //             .push_slice(&[0u8;3]).push_opcode(OP_CAT)
    //         .push_opcode(OP_ENDIF);

    //     builder
    // }

    // creates a sig on (time || msg_32)
    fn sign_timestamp(txid: [u8; 32]) -> ([u8; 32], secp256k1::Signature) {
        let timestamp_srv_priv_key =
            bitcoin::PrivateKey::from_wif("cMtnxwXc1JEAzRzi6xCGEm4Vig7ECcW4JyczPfyhwpjBiDAJPeDP")
                .unwrap();
        let mut eng = SigHash::engine();
        //  code for get actual time. Format goes here
        let time = [13u8; 32]; // do the encoding stuff properly here
        eng.input(&time);
        eng.input(&txid);
        let msg = secp256k1::Message::from_slice(&SigHash::from_engine(eng)).unwrap();
        let secp = Secp256k1::signing_only();
        (time, secp.sign(&msg, &timestamp_srv_priv_key.key))
    }

    // Format the fee-into to the desired format
    // fee is specified in amount per single-satoshi-fee
    // We convert the binary encoding by replacing all ones
    // in the binary representation with the positions of ones
    // in the system and removing all the zeros.
    // We specify fees in 12 bits(2**12 = 4096)
    // approximately multiples of 0.025%.
    // This assumes that fees must be less than 2^48 (> 2 million BTC).
    // Club the fee representation into two groups of 6 bits each
    // For example fee = 100 (1 sat per 100 sats sent) or 1%
    // Each character is a byte.
    // 101 = [0 0 0 0 0  1] [1 0 0 1 0 1] (12 bits total)
    //     =  [0 - 1]  [5 2 0 -1] //-1 is split delimiter
    //     =  [0 -1 5 2 0 -1] as u8 array.
    fn calc_fee_repr(fee: u16) -> Vec<u8> {
        assert!(fee < 4096);
        let r = (fee % 64) as u8;
        let l = (fee / 64) as u8;
        let mut ret = vec![];
        println!("{}:{}", l, r);
        ret.extend(fee_helper(l));
        ret.extend(fee_helper(r));
        ret
    }

    fn fee_helper(f: u8) -> Vec<u8> {
        assert!(f < 64);
        let mut ret = vec![];
        for i in (0..6).rev() {
            let mask = 0x01 << i;
            if (mask & f).count_ones() >= 1 {
                ret.push(i as u8)
            }
        }
        ret.push(0x4f); //encoding of -1
        ret
    }

    // Pad a 32 byte blob with timestamp(32 byte) and
    // Assumes some encoding of timestamp as 32 bytes
    // creates a sig on (time || msg_32)
    fn sign_fee(time: [u8; 32]) -> (Vec<u8>, secp256k1::Signature) {
        let fee_collector_srv_priv_key =
            bitcoin::PrivateKey::from_wif("cPNAjBG689Yj71yRwybLvF1uUDVWA9gB2CwDynoUq5CQRNciBa77")
                .unwrap();
        let mut eng = SigHash::engine();
        //  code for get actual time. Format goes here
        let fee = calc_fee_repr(100); // do the encoding stuff properly here
        eng.input(&time);
        eng.input(&fee);
        let msg = secp256k1::Message::from_slice(&SigHash::from_engine(eng)).unwrap();
        let secp = Secp256k1::signing_only();
        (fee, secp.sign(&msg, &fee_collector_srv_priv_key.key))
    }

    fn finalize(ctx: &mut CovenantTxContext) {
        // Set the relevant outputs
        let change_amt = get_exp_amt(ctx.change_amt);
        let sent_amt = get_exp_amt(ctx.sent_amt);
        let fee_amt = get_exp_amt(ctx.fee_amt);

        let btc_ast = confidential::Asset::Explicit(AssetId::from_inner(Midstate(BTC_ASSET)));
        let mut btc_ast_plus_exp_pref = serialize(&btc_ast);
        btc_ast_plus_exp_pref.push(1u8);

        let pre_code = pre_code_sep(&ctx.cov_script_ctx).into_script().into_bytes();
        let script_code = post_code_sep(
            Builder::new(),
            hash160::Hash::hash(&pre_code).into_inner(),
            ctx.cov_script_ctx.redeem_pk,
        )
        .into_script();

        let script_pubkey = get_covenant_script(&ctx.cov_script_ctx);
        let sighash_msg: Vec<u8>;
        let redeem_sig;
        {
            let tx = &mut ctx.tx;
            // The first output must be fee output
            tx.output.push(TxOut::default());
            tx.output[0].asset = ctx.cov_script_ctx.traded_asset;
            tx.output[0].value = ctx.fee_amt;
            tx.output[0].nonce = confidential::Nonce::Null;
            tx.output[0].script_pubkey = ctx.cov_script_ctx.fee_collector_wsh.clone();

            tx.output.push(TxOut::default());
            // The second output is reciver amount
            tx.output[1].asset = ctx.cov_script_ctx.traded_asset;
            tx.output[1].value = ctx.sent_amt;
            tx.output[1].nonce = confidential::Nonce::Null;
            {
                let mut output_ctx = ctx.cov_script_ctx.clone();
                // change pk
                output_ctx.redeem_pk = ctx.receiver_pk;
                tx.output[1].script_pubkey = get_covenant_script(&output_ctx).to_v0_p2wsh();
            }

            tx.output.push(TxOut::default());
            // The third output is the change output
            tx.output[2].asset = ctx.cov_script_ctx.traded_asset;
            tx.output[2].value = ctx.change_amt;
            tx.output[2].nonce = confidential::Nonce::Null;
            tx.output[2].script_pubkey = script_pubkey.to_v0_p2wsh();

            tx.output.push(TxOut::default());
            // The final output is bitcoin fees output
            tx.output[3].asset = btc_ast;
            tx.output[3].value = ctx.tx_fee_btc;
            tx.output[3].nonce = confidential::Nonce::Null;
            tx.output[3].script_pubkey = Script::new();
        }
        let tx = &ctx.tx;
        let mut cache = SigHashCache::new(tx);
        let sighash_type = SigHashType::from_u32(1); //sighash all
        let actual_result = cache.signature_hash(
            0,
            &script_code,
            confidential::Value::Explicit(0x0000000005f5e100),
            sighash_type,
        );

        let secp = Secp256k1::new();
        sighash_msg = actual_result.clone().into_iter().flatten().collect();
        let mut eng = SigHash::engine();
        eng.input(&sighash_msg);
        let sighash_u256 = SigHash::from_engine(eng);

        let sig = secp.sign(
            &bitcoin::secp256k1::Message::from_slice(&sighash_u256[..]).unwrap(),
            &ctx.redeem_priv_key.key,
        );
        redeem_sig = Vec::from(sig.serialize_der().as_ref());

        let mut cache = SigHashCache::new(tx);
        let timestamp_txid = cache.timestamp_txid(sighash_type);
        let (time, timestamp_sig) = sign_timestamp(timestamp_txid.into_inner());
        let (fee, fee_sig) = sign_fee(time);

        let stk = vec![
            redeem_sig,
            serialize(&u64::swap_bytes(change_amt)),
            serialize(&u64::swap_bytes(sent_amt)),
            serialize(&u64::swap_bytes(fee_amt)),
            ctx.receiver_pk.to_bytes(),
            btc_ast_plus_exp_pref,
            Vec::from(&serialize(&tx.output[3])[34..]),
            Vec::from(timestamp_sig.serialize_der().as_ref()),
            Vec::from(time),
            Vec::from(fee),
            Vec::from(fee_sig.serialize_der().as_ref()),
            vec![8], //fee elem
            vec![4], //num_zeros
            vec![],  //num_zeros
            vec![],  //num_zeros
            vec![4], //num_zeros
            sighash_msg,
            pre_code,
            script_pubkey.into_bytes(),
        ];
        let input = &mut ctx.tx.input[ctx.index];
        input.witness.script_witness = stk;
    }

    fn hash_verify(builder: Builder, h: [u8; 20]) -> Builder {
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
    fn post_code_sep(builder: Builder, h: [u8; 20], redeem_pk: bitcoin::PublicKey) -> Builder {
        let builder = hash_verify(builder, h);
        // pub pubkey
        assert!(redeem_pk.compressed);
        let builder = builder.push_key(&redeem_pk);

        // Post script
        let builder = builder
            .push_int(2)
            .push_opcode(OP_PICK)
            .push_int(1)
            .push_opcode(OP_CAT)
            .push_opcode(OP_OVER)
            .push_opcode(OP_CHECKSIGVERIFY)
            .push_opcode(OP_SWAP)
            .push_opcode(OP_SHA256)
            .push_opcode(OP_SWAP)
            .push_opcode(OP_CHECKSIGFROMSTACK);
        builder
    }

    fn pre_code_sep(ctx: &CovenantScriptContext) -> Builder {
        let asset = ctx.traded_asset;
        let fee_srv_pk = ctx.fee_collector_srv_pk;
        let fee_collector_wsh = &ctx.fee_collector_wsh;
        let timestamp_srv_pk = ctx.timestamp_srv_pk;
        // let mut stk = vec![ser_sig, serialize(&1000_000_u64), serialize(&98_000_000_u64),serialize(&1000_000_u64), recv_pk, btc_fee_asset, btc_asset_ser, sighash_msg, pre_code];
        let mut stk_size = 18;
        let builder = Builder::new();
        let builder = builder
            .push_opcode(OP_OVER)
            // Now create the post script from script pubkey.
            // The stack contains [sig sighash pre sighash]
            // First get the hashoutputs from sighash
            .push_opcode(OP_DUP);
        stk_size += 2;
        // Calulate the len of post_script by feeding in dummy values
        let post_code_sep_len;
        {
            let pk = bitcoin::PublicKey::from_slice(&[0x02; 33]).unwrap();
            post_code_sep_len =
                serialize(&post_code_sep(Builder::new(), [0u8; 20], pk).into_script()).len();
        }
        let outpoint_start = 4 + 32 + 32 + 32;
        let hashouputs_start = 4 + 32 + 32 + 32 + (32 + 4) + post_code_sep_len + 9 + 4;
        let script_pubkey_start = 4 + 32 + 32 + 32 + (32 + 4) + 1; // assumes 1 byte len

        // Get the custom txid for the transaction onto the alt-stack
        // Calculated as
        // SHA2(version|| hashsequences || hashinputs || hashissuances|| hashoutputs||locktime || sighashflag)
        let builder = builder
            .push_opcode(OP_2DUP)
            .push_int(outpoint_start)
            .push_opcode(OP_LEFT)
            .push_opcode(OP_SWAP)
            .push_int(hashouputs_start as i64)
            .push_opcode(OP_RIGHT)
            .push_opcode(OP_CAT)
            .push_opcode(OP_SHA256)
            .push_opcode(OP_TOALTSTACK);
        let builder = builder
            .push_int(hashouputs_start as i64)
            .push_int(32)
            .push_opcode(OP_SUBSTR)
            .push_opcode(OP_TOALTSTACK);
        stk_size += -1;
        // Next get the change sha2(scriptpubkey)
        let builder = builder
            .push_int(script_pubkey_start)
            .push_int((post_code_sep_len - 1) as i64)
            .push_opcode(OP_SUBSTR)
            .push_opcode(OP_2DUP)
            .push_opcode(OP_CAT)
            // Now the redeem script is top of stack
            .push_opcode(OP_SHA256)
            .push_opcode(OP_TOALTSTACK);
        stk_size += 0;
        // The len
        let pre_publickey_push_len = hash_verify(Builder::new(), [0u8; 20]).into_script().len();
        let builder = builder
            .push_opcode(OP_DUP)
            .push_int((pre_publickey_push_len + 1) as i64) // + 1 for 0x21(len of pk)
            .push_opcode(OP_LEFT)
            .push_int((stk_size + 1) - 5)
            .push_opcode(OP_ROLL)
            //now stack is [.. script_pk pre pk]
            .push_opcode(OP_CAT)
            .push_opcode(OP_SWAP)
            .push_int((pre_publickey_push_len + 34) as i64)
            .push_opcode(OP_RIGHT)
            .push_opcode(OP_CAT)
            .push_opcode(OP_OVER)
            .push_opcode(OP_SWAP)
            .push_opcode(OP_CAT)
            // now stack is [.. script_pk_receiver]
            .push_opcode(OP_SHA256)
            .push_opcode(OP_TOALTSTACK);
        stk_size -= 2;
        // Process the fee output
        let mut pre_value_blob = vec![];
        pre_value_blob.extend(&serialize(&asset)); // asset
        pre_value_blob.push(1u8); // explicit prefix;
        let mut post_value_blob = vec![0u8]; // nonce
        assert!(fee_collector_wsh.is_v0_p2wsh());
        post_value_blob.extend(serialize(fee_collector_wsh));
        let builder = builder.push_slice(&pre_value_blob).push_opcode(OP_DUP);
        stk_size += 2;
        let builder = builder
            .push_int(stk_size - 4)
            .push_opcode(OP_PICK)
            .push_opcode(OP_SIZE)
            .push_int(8)
            .push_opcode(OP_EQUALVERIFY)
            .push_opcode(OP_CAT) // value; deal with this later
            .push_slice(&post_value_blob)
            .push_opcode(OP_CAT)
            .push_opcode(OP_SWAP);
        stk_size += 0;
        // Process the other reiever output
        let builder = builder
            .push_opcode(OP_DUP)
            .push_int((stk_size + 1) - 3)
            .push_opcode(OP_PICK)
            .push_opcode(OP_SIZE)
            .push_int(8)
            .push_opcode(OP_EQUALVERIFY)
            .push_opcode(OP_CAT)
            .push_slice(&[0u8, 34u8, 0u8, 32u8])
            .push_opcode(OP_CAT)
            .push_opcode(OP_FROMALTSTACK)
            .push_opcode(OP_CAT)
            .push_opcode(OP_SWAP);
        stk_size += 1;
        // Get the target and change outputs.
        let builder = builder
            .push_opcode(OP_DUP)
            .push_int((stk_size + 1) - 2)
            .push_opcode(OP_PICK)
            .push_opcode(OP_SIZE)
            .push_int(8)
            .push_opcode(OP_EQUALVERIFY)
            .push_opcode(OP_CAT)
            .push_slice(&[0u8, 34u8, 0u8, 32u8])
            .push_opcode(OP_CAT)
            .push_opcode(OP_FROMALTSTACK)
            .push_opcode(OP_CAT)
            .push_opcode(OP_SWAP);
        // same stk size here as the start
        stk_size += 1;
        let builder = builder
            .push_int(stk_size - 5)
            .push_opcode(OP_ROLL)
            .push_opcode(OP_DUP)
            .push_opcode(OP_ROT)
            .push_opcode(OP_EQUAL)
            .push_int(0)
            .push_opcode(OP_EQUALVERIFY);
        //
        stk_size -= 1;
        let builder = builder
            .push_int(stk_size - 5)
            .push_opcode(OP_ROLL)
            // check size
            .push_opcode(OP_SIZE)
            .push_int(8 + 1 + 1)
            .push_opcode(OP_EQUALVERIFY)
            .push_opcode(OP_CAT);
        stk_size -= 1;

        let builder = builder
            .push_opcode(OP_CAT)
            .push_opcode(OP_CAT)
            .push_opcode(OP_CAT);
        stk_size -= 3;
        // now sighash for hashoutputs in on the top of stack
        let builder = builder
            .push_opcode(OP_HASH256)
            .push_opcode(OP_FROMALTSTACK)
            .push_opcode(OP_EQUALVERIFY);
        stk_size -= 1;
        assert_eq!(stk_size, 15);

        // Now check the sigs and fee calculation
        // Attest that the timestamping server digest is correct
        // The top of stack now contains the timestamp
        // timestamp is assumed to be 32 bytes

        let builder = builder.push_int(stk_size - 5).push_opcode(OP_ROLL);
        let builder = builder
            .push_int(stk_size - 5)
            .push_opcode(OP_PICK)
            .push_opcode(OP_FROMALTSTACK)
            .push_opcode(OP_CAT)
            .push_opcode(OP_SHA256);
        let builder = builder
            .push_key(&timestamp_srv_pk)
            .push_opcode(OP_CHECKSIGFROMSTACKVERIFY);
        stk_size -= 1;

        // Now timestamp sig is check
        let builder = builder
            .push_int(stk_size - 5)
            .push_opcode(OP_ROLL)
            .push_int(stk_size - 5)
            .push_opcode(OP_PICK)
            .push_opcode(OP_CAT)
            .push_opcode(OP_SHA256)
            .push_int(stk_size - 6)
            .push_opcode(OP_ROLL)
            .push_opcode(OP_SWAP);
        let builder = builder
            .push_key(&fee_srv_pk)
            .push_opcode(OP_CHECKSIGFROMSTACKVERIFY);
        // Now timestamp and fee are checkec
        stk_size -= 2;
        // Push all the required zeros onto the top of stack
        let builder = builder
            .push_slice(&[])
            .push_slice(&[0x00])
            .push_slice(&[0x00, 0x00])
            .push_slice(&[0x00, 0x00, 0x00])
            .push_slice(&[0x00, 0x00, 0x00, 0x00])
            .push_slice(&[0x00, 0x00, 0x00, 0x00, 0x00]);
        stk_size += 6;
        // Bring the fee onto the top
        let builder = builder.push_int(stk_size - 2).push_opcode(OP_PICK);
        stk_size += 1;
        let builder = convert_amt_three_bytes_to_script_num(builder, &mut stk_size, 7);
        assert_eq!(stk_size, 17);
        let builder = builder.push_int(stk_size - 3).push_opcode(OP_PICK);
        stk_size += 1;
        let builder = convert_sent_amt_to_script_num(builder, &mut stk_size, 7);
        let builder = compare_script_nums(builder, &mut stk_size);
        // let builder = perform_add(builder, &mut stk_size);
        assert_eq!(stk_size, 13);
        // stk_size -= 0;
        // let builder = builder.push_int(stk_size - 2).push_opcode(OP_PICK);
        // let builder = convert_amt_three_bytes_to_script_num(builder, (stk_size + 2) - 6, 5);
        // stk_size -= 0;
        // let builder = convert_amt_three_bytes_to_script_num(builder, (stk_size + 2) - 6, 3);
        // stk_size -= 0;

        let builder = builder
            .push_int(stk_size - 2)
            .push_opcode(OP_ROLL)
            .push_opcode(OP_DROP);
        stk_size -= 1;
        let builder = builder
            .push_int(stk_size - 2)
            .push_opcode(OP_ROLL)
            .push_opcode(OP_DROP);
        stk_size -= 1;
        let builder = builder
            .push_int(stk_size - 2)
            .push_opcode(OP_ROLL)
            .push_opcode(OP_DROP);
        stk_size -= 1;
        let builder = builder
            .push_int(stk_size - 2)
            .push_opcode(OP_ROLL)
            .push_opcode(OP_DROP);
        stk_size -= 1;
        let builder = builder
            .push_opcode(OP_2DROP)
            .push_opcode(OP_2DROP)
            .push_opcode(OP_2DROP);
        builder.push_opcode(OP_CODESEPARATOR)
    }

    fn get_covenant_script(ctx: &CovenantScriptContext) -> Script {
        // Create a covenant that captures value
        // Create a pre-script
        let builder = pre_code_sep(ctx);
        let h = hash160::Hash::hash(&builder.clone().into_script().as_bytes());
        let script = post_code_sep(builder, h.into_inner(), ctx.redeem_pk).into_script();
        script
    }

    fn get_exp_amt(amt: confidential::Value) -> u64 {
        if let confidential::Value::Explicit(x) = amt {
            x
        } else {
            panic!("Must have explicit amounts");
        }
    }

    #[test]
    fn simple_covenant() {
        use bitcoin_hashes::hex::FromHex;
        let traded_asset =
            AssetId::from_hex("18f50776a4d8966b84e68ffdd586577601bf630779502e0ee41c612627d07363")
                .unwrap();
        let traded_asset = confidential::Asset::Explicit(traded_asset);

        // create some random keys
        let redeem_pk = bitcoin::PublicKey::from_str(
            "02a05cab7cf0e66e6684b22c15fa524ffcff8913a9088780ecccc3e7b10baaaa81",
        )
        .unwrap();
        let redeem_priv_key =
            bitcoin::PrivateKey::from_wif("cVGQewjMcqa5PBvSvid8XeqoKA66YsVf6U9EkbgR4HFhU6DHsrEg")
                .unwrap();
        let fee_collector_srv_pk = bitcoin::PublicKey::from_str(
            "02d34800ac89c2f27ae8938c2ea370bd63d5d47926d71243deb492966d1e37e355",
        )
        .unwrap();
        let fee_collector_srv_priv_key =
            bitcoin::PrivateKey::from_wif("cPNAjBG689Yj71yRwybLvF1uUDVWA9gB2CwDynoUq5CQRNciBa77")
                .unwrap();
        let timestamp_srv_pk = bitcoin::PublicKey::from_str(
            "03642e750575c0692c7c6984f5eb3ceaa81a619820eee2290caeeb7affc303abdb",
        )
        .unwrap();
        let timestamp_srv_priv_key =
            bitcoin::PrivateKey::from_wif("cMtnxwXc1JEAzRzi6xCGEm4Vig7ECcW4JyczPfyhwpjBiDAJPeDP")
                .unwrap();
        let receiver_pk = bitcoin::PublicKey::from_str(
            "032e58afe51f9ed8ad3cc7897f634d881fdbe49a81564629ded8156bebd2ffd1af",
        )
        .unwrap();

        let secp = Secp256k1::new();
        assert!(redeem_pk == redeem_priv_key.public_key(&secp));
        assert!(fee_collector_srv_pk == fee_collector_srv_priv_key.public_key(&secp));
        assert!(timestamp_srv_pk == timestamp_srv_priv_key.public_key(&secp));

        // Create a legit script here
        // Right now; anyone can spend wsh
        let fee_collector_wsh = Builder::new().push_int(1).into_script();

        let cov_script_ctx = CovenantScriptContext {
            traded_asset: traded_asset,
            redeem_pk: redeem_pk,
            fee_collector_wsh: fee_collector_wsh.to_v0_p2wsh(),
            // server pks
            fee_collector_srv_pk: fee_collector_srv_pk,
            timestamp_srv_pk: timestamp_srv_pk,
        };

        let script_pubkey = get_covenant_script(&cov_script_ctx);
        println!("{}", &script_pubkey);
        // tx.output[0].script_pubkey = script_pubkey.to_v0_p2wsh();

        println!(
            "asset: {}",
            address::Address::p2wsh(&script_pubkey, None, &AddressParams::ELEMENTS)
        );
        println!(
            "btc: {}",
            address::Address::p2wsh(&fee_collector_wsh, None, &AddressParams::ELEMENTS)
        );
        // println!("script_wsh: {}", script_pubkey.to_v0_p2wsh());
        // println!("{}", serialize_hex(&tx));

        // Now create a transaction spending this.
        let spend_tx = Transaction {
            version: 2,
            lock_time: 0,
            input: vec![
                txin_from_txid_vout(
                    "26c40e0eefe4b15c2114f676651909a8d9e06be2006f2427d8628a0ae73fabb6",
                    1,
                ), //asset
                txin_from_txid_vout(
                    "f552c401e3a81a7ac2dd488a2ee9005331da2c3ffe5de7f7d08a220050afabe4",
                    1,
                ), //btc
            ],
            output: vec![],
        };

        let mut ctx = CovenantTxContext {
            tx: spend_tx,
            index: 0,
            // The covenant script context
            cov_script_ctx: cov_script_ctx,
            receiver_pk: receiver_pk,
            //amts
            sent_amt: confidential::Value::Explicit(98_000_000_u64),
            change_amt: confidential::Value::Explicit(1_000_000_u64),
            fee_amt: confidential::Value::Explicit(1_000_000_u64),
            tx_fee_btc: confidential::Value::Explicit(1_000_000_u64),

            redeem_priv_key: redeem_priv_key,

            // Sigs and msgs
            timestamp_srv_msg: vec![],
            timestamp_srv_sig: vec![],
            fee_srv_msg: vec![],
            fee_srv_sig: vec![],
        };

        finalize(&mut ctx);
        let mut stk = ctx.tx.input[0].witness.script_witness.clone();
        stk.pop().unwrap();
        println!(
            "Max elem len: {}",
            stk.clone().into_iter().map(|v| v.len()).max().unwrap()
        );

        let mut spend_tx = ctx.tx;
        let mut ser_out = vec![];
        for tx_out in &spend_tx.output {
            ser_out.extend(serialize(tx_out));
        }
        let mut interp = interpreter::State::init_witness(stk.clone());
        interp.execute_script(script_pubkey.clone());

        stk.push(script_pubkey.clone().into_bytes());
        spend_tx.input[0].witness.script_witness = stk;
        spend_tx.input[1].witness.script_witness = vec![fee_collector_wsh.to_bytes()];
        println!("{}", serialize_hex(&spend_tx));
    }

    fn txin_from_txid_vout(txid: &str, vout: u32) -> TxIn {
        TxIn {
            previous_output: OutPoint {
                txid: Txid::from_str(txid).unwrap(),
                vout: vout,
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
        }
    }
}
