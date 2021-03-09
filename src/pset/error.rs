// Rust Bitcoin Library
// Written by
//   The Rust Bitcoin developers
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

use std::{error, fmt};

use Txid;
use encode;
use super::raw;

use hashes;

#[derive(Copy, Clone, PartialEq, Eq, Debug)]
/// Enum for marking pset hash error
pub enum PsetHash {
    Ripemd,
    Sha256,
    Hash160,
    Hash256,
}
/// Ways that a Partially Signed Transaction might fail.
#[derive(Clone, PartialEq, Eq, Debug)]
pub enum Error {
    /// Magic bytes for a PSET must be the ASCII for "pset" serialized in most
    /// significant byte order.
    InvalidMagic,
    /// The separator for a PSET must be `0xff`.
    InvalidSeparator,
    /// Known keys must be according to spec.
    InvalidKey(raw::Key),
    /// Non-proprietary key type found when proprietary key was expected
    InvalidProprietaryKey,
    /// Keys within key-value map should never be duplicated.
    DuplicateKey(raw::Key),
    /// PSET has an input exclusively requiring a height-based locktime and also
    /// an input requiring a time-based locktime
    LocktimeConflict,
    /// The scriptSigs for the unsigned transaction must be empty.
    UnsignedTxHasScriptSigs,
    /// The scriptWitnesses for the unsigned transaction must be empty.
    UnsignedTxHasScriptWitnesses,
    /// A PSET must have an unsigned transaction.
    MustHaveUnsignedTx,
    /// Signals that there are no more key-value pairs in a key-value map.
    NoMorePairs,
    /// Attempting to merge with a PSET describing a different unsigned
    /// transaction.
    UniqueIdMismatch {
        /// Expected
        expected: Txid,
        /// Actual
        actual: Txid,
    },
    /// Unable to parse as a standard SigHash type.
    NonStandardSigHashType(u32),
    /// Parsing errors from bitcoin_hashes
    HashParseError(hashes::Error),
    /// The pre-image must hash to the correponding pset hash
    InvalidPreimageHashPair {
        /// Hash-type
        hash_type: PsetHash,
        /// Pre-image
        preimage: Vec<u8>,
        /// Hash value
        hash: Vec<u8>,
    },
    /// Data inconsistency/conflicting data during merge procedure
    MergeConflict(String),
    /// Serialization error in bitcoin consensus-encoded structures
    ConsensusEncoding,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            Error::InvalidKey(ref rkey) => write!(f, "invalid key: {}", rkey),
            Error::InvalidProprietaryKey => write!(f, "non-proprietary key type found when proprietary key was expected"),
            Error::DuplicateKey(ref rkey) => write!(f, "duplicate key: {}", rkey),
            Error::LocktimeConflict => write!(f, "conflicting locktime requirements"),
            Error::UniqueIdMismatch { expected: ref e, actual: ref a } => write!(f, "different id: expected {}, actual {}", e, a),
            Error::NonStandardSigHashType(ref sht) => write!(f, "non-standard sighash type: {}", sht),
            Error::InvalidMagic => f.write_str("invalid magic"),
            Error::InvalidSeparator => f.write_str("invalid separator"),
            Error::UnsignedTxHasScriptSigs => f.write_str("the unsigned transaction has script sigs"),
            Error::UnsignedTxHasScriptWitnesses => f.write_str("the unsigned transaction has script witnesses"),
            Error::MustHaveUnsignedTx => {
                f.write_str("partially signed transactions must have an unsigned transaction")
            }
            Error::NoMorePairs => f.write_str("no more key-value pairs for this pset map"),
            Error::HashParseError(e) => write!(f, "Hash Parse Error: {}", e),
            Error::InvalidPreimageHashPair{ref preimage, ref hash, ref hash_type} => {
                // directly using debug forms of psethash enums
                write!(f, "Preimage {:?} does not match {:?} hash {:?}", preimage, hash_type, hash )
            }
            Error::MergeConflict(ref s) => { write!(f, "Merge conflict: {}", s) }
            Error::ConsensusEncoding => f.write_str("bitcoin consensus encoding error"),
        }
    }
}

impl error::Error for Error {}

#[doc(hidden)]
impl From<hashes::Error> for Error {
    fn from(e: hashes::Error) -> Error {
        Error::HashParseError(e)
    }
}

impl From<encode::Error> for Error {
    fn from(err: encode::Error) -> Self {
        match err {
            encode::Error::PsetError(err) => err,
            _ => Error::ConsensusEncoding,
        }
    }
}
