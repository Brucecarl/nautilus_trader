// -------------------------------------------------------------------------------------------------
//  Copyright (C) 2015-2026 Nautech Systems Pty Ltd. All rights reserved.
//  https://nautechsystems.io
//
//  Licensed under the GNU Lesser General Public License Version 3.0 (the "License");
//  You may not use this file except in compliance with the License.
//  You may obtain a copy of the License at https://www.gnu.org/licenses/lgpl-3.0.en.html
//
//  Unless required by applicable law or agreed to in writing, software
//  distributed under the License is distributed on an "AS IS" BASIS,
//  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
//  See the License for the specific language governing permissions and
//  limitations under the License.
// -------------------------------------------------------------------------------------------------

//! EIP-712 order signing for the Polymarket CTF Exchange.
//!
//! Orders on Polymarket are signed typed structured data (EIP-712) against the
//! CTF Exchange contract on Polygon. Two exchange contracts exist:
//! - [`CTF_EXCHANGE`]: Standard binary markets.
//! - [`NEG_RISK_CTF_EXCHANGE`]: Negative-risk (multi-outcome) markets.
//!
//! Both share the same EIP-712 domain name and version; only the
//! `verifyingContract` differs.

use std::str::FromStr;

use alloy::{
    signers::{SignerSync, local::PrivateKeySigner},
    sol_types::{SolStruct, eip712_domain},
};
use alloy_primitives::{Address, B256, U256, address};
use rust_decimal::Decimal;

use crate::{
    common::{consts::CHAIN_ID, credential::EvmPrivateKey, enums::PolymarketOrderSide},
    http::{
        error::{Error, Result},
        models::PolymarketOrder,
    },
};

// L1 ClobAuth constants
const CLOB_AUTH_DOMAIN_NAME: &str = "ClobAuthDomain";
const CLOB_AUTH_DOMAIN_VERSION: &str = "1";
const CLOB_AUTH_MESSAGE: &str = "This message attests that I control the given wallet";

/// CTF Exchange contract address on Polygon mainnet (v2).
pub const CTF_EXCHANGE: Address = address!("0xE111180000d2663C0091e4f400237545B87B996B");

/// Neg Risk CTF Exchange contract address on Polygon mainnet (v2).
pub const NEG_RISK_CTF_EXCHANGE: Address = address!("0xe2222d279d744050d28e00520010520000310F59");

const DOMAIN_NAME: &str = "Polymarket CTF Exchange";
const DOMAIN_VERSION: &str = "2";

// EIP-712 ClobAuth struct for L1 API authentication.
//
// Reference: <https://docs.polymarket.com/api-reference/authentication#l1-authentication>
alloy::sol! {
    struct ClobAuth {
        address address;
        string timestamp;
        uint256 nonce;
        string message;
    }
}

// EIP-712 Order struct matching the CTFExchange v2 contract.
//
// Note: `expiration` is sent in the API payload but is NOT part of the signed struct.
// Reference: <https://github.com/Polymarket/clob-client-v2/blob/main/src/order-utils/model/ctfExchangeV2TypedData.ts>
alloy::sol! {
    struct Order {
        uint256 salt;
        address maker;
        address signer;
        uint256 tokenId;
        uint256 makerAmount;
        uint256 takerAmount;
        uint8 side;
        uint8 signatureType;
        uint256 timestamp;
        bytes32 metadata;
        bytes32 builder;
    }
}

/// EIP-712 order signer for the Polymarket CTF Exchange.
#[derive(Debug)]
pub struct OrderSigner {
    signer: PrivateKeySigner,
}

impl OrderSigner {
    /// Creates a new [`OrderSigner`] from an EVM private key.
    pub fn new(private_key: &EvmPrivateKey) -> Result<Self> {
        let key_hex = private_key
            .as_hex()
            .strip_prefix("0x")
            .unwrap_or(private_key.as_hex());
        let signer = PrivateKeySigner::from_str(key_hex)
            .map_err(|e| Error::bad_request(format!("Failed to create signer: {e}")))?;
        Ok(Self { signer })
    }

    /// Returns the signer's Ethereum address.
    #[must_use]
    pub fn address(&self) -> Address {
        self.signer.address()
    }

    /// Signs a [`PolymarketOrder`] and returns the hex-encoded ECDSA signature.
    ///
    /// The `neg_risk` flag selects which exchange contract to use as the
    /// EIP-712 `verifyingContract`. Uses the Polygon mainnet chain ID (137).
    ///
    /// # Errors
    ///
    /// Returns an error if `order.signer` does not match this signer's address.
    pub fn sign_order(&self, order: &PolymarketOrder, neg_risk: bool) -> Result<String> {
        self.sign_order_with_chain_id(order, neg_risk, CHAIN_ID)
    }

    /// Signs a [`PolymarketOrder`] with an explicit `chain_id`.
    ///
    /// Use this when targeting a non-mainnet environment (e.g. Amoy testnet, chain ID 80002).
    ///
    /// # Errors
    ///
    /// Returns an error if `order.signer` does not match this signer's address.
    pub fn sign_order_with_chain_id(
        &self,
        order: &PolymarketOrder,
        neg_risk: bool,
        chain_id: u64,
    ) -> Result<String> {
        let order_signer = parse_address(&order.signer, "signer")?;
        if order_signer != self.signer.address() {
            return Err(Error::bad_request(format!(
                "Order signer {order_signer} does not match local signer {}",
                self.signer.address(),
            )));
        }

        let eip712_order = build_eip712_order(order)?;

        let contract = if neg_risk {
            NEG_RISK_CTF_EXCHANGE
        } else {
            CTF_EXCHANGE
        };

        let domain = eip712_domain! {
            name: DOMAIN_NAME,
            version: DOMAIN_VERSION,
            chain_id: chain_id,
            verifying_contract: contract,
        };

        let signing_hash = eip712_order.eip712_signing_hash(&domain);
        self.sign_hash(&signing_hash.0)
    }

    fn sign_hash(&self, hash: &[u8; 32]) -> Result<String> {
        let hash_b256 = B256::from(*hash);
        let signature = self
            .signer
            .sign_hash_sync(&hash_b256)
            .map_err(|e| Error::bad_request(format!("Failed to sign order: {e}")))?;

        let r = signature.r();
        let s = signature.s();
        let v = if signature.v() { 28u8 } else { 27u8 };

        Ok(format!("0x{r:064x}{s:064x}{v:02x}"))
    }
}

/// Signs a ClobAuth EIP-712 message for L1 API authentication.
///
/// Used to create or derive API credentials via the CLOB `/auth/api-key`
/// and `/auth/derive-api-key` endpoints.
///
/// Returns `(signer_address_hex, signature_hex)`.
pub fn sign_clob_auth(
    private_key: &EvmPrivateKey,
    timestamp: &str,
    nonce: u64,
) -> Result<(String, String)> {
    sign_clob_auth_with_chain_id(private_key, timestamp, nonce, CHAIN_ID)
}

/// Signs a ClobAuth EIP-712 message with an explicit `chain_id`.
///
/// Use this when targeting a non-mainnet environment (e.g. Amoy testnet, chain ID 80002).
///
/// Returns `(signer_address_hex, signature_hex)`.
pub fn sign_clob_auth_with_chain_id(
    private_key: &EvmPrivateKey,
    timestamp: &str,
    nonce: u64,
    chain_id: u64,
) -> Result<(String, String)> {
    let key_hex = private_key
        .as_hex()
        .strip_prefix("0x")
        .unwrap_or(private_key.as_hex());
    let signer = PrivateKeySigner::from_str(key_hex)
        .map_err(|e| Error::bad_request(format!("Failed to create signer: {e}")))?;

    let address = signer.address();

    let auth = ClobAuth {
        address,
        timestamp: timestamp.to_string(),
        nonce: U256::from(nonce),
        message: CLOB_AUTH_MESSAGE.to_string(),
    };

    let domain = eip712_domain! {
        name: CLOB_AUTH_DOMAIN_NAME,
        version: CLOB_AUTH_DOMAIN_VERSION,
        chain_id: chain_id,
    };

    let signing_hash = auth.eip712_signing_hash(&domain);
    let signature = signer
        .sign_hash_sync(&signing_hash)
        .map_err(|e| Error::bad_request(format!("Failed to sign ClobAuth: {e}")))?;

    let r = signature.r();
    let s = signature.s();
    let v = if signature.v() { 28u8 } else { 27u8 };

    Ok((
        format!("{address:#x}"),
        format!("0x{r:064x}{s:064x}{v:02x}"),
    ))
}

// Converts a PolymarketOrder to the EIP-712 Order struct
fn build_eip712_order(order: &PolymarketOrder) -> Result<Order> {
    Ok(Order {
        salt: U256::from(order.salt),
        maker: parse_address(&order.maker, "maker")?,
        signer: parse_address(&order.signer, "signer")?,
        tokenId: U256::from_str(order.token_id.as_str())
            .map_err(|e| Error::bad_request(format!("Invalid token ID: {e}")))?,
        makerAmount: decimal_to_u256(order.maker_amount, "maker_amount")?,
        takerAmount: decimal_to_u256(order.taker_amount, "taker_amount")?,
        side: order_side_to_u8(order.side),
        signatureType: order.signature_type as u8,
        timestamp: U256::from(order.timestamp),
        metadata: order.metadata,
        builder: order.builder,
    })
}

fn parse_address(addr: &str, field: &str) -> Result<Address> {
    Address::from_str(addr).map_err(|e| Error::bad_request(format!("Invalid {field} address: {e}")))
}

fn decimal_to_u256(d: Decimal, field: &str) -> Result<U256> {
    let normalized = d.normalize();
    if normalized.scale() != 0 {
        return Err(Error::bad_request(format!("{field} must be an integer")));
    }
    let mantissa = normalized.mantissa();
    if mantissa < 0 {
        return Err(Error::bad_request(format!("{field} must be non-negative")));
    }
    Ok(U256::from(mantissa as u128))
}

fn order_side_to_u8(side: PolymarketOrderSide) -> u8 {
    match side {
        PolymarketOrderSide::Buy => 0,
        PolymarketOrderSide::Sell => 1,
    }
}

#[cfg(test)]
mod tests {
    use alloy_primitives::keccak256;
    use rstest::rstest;
    use rust_decimal_macros::dec;
    use ustr::Ustr;

    use super::*;
    use crate::common::enums::SignatureType;

    const TEST_PRIVATE_KEY: &str =
        "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80";

    fn test_signer() -> OrderSigner {
        let pk = EvmPrivateKey::new(TEST_PRIVATE_KEY).unwrap();
        OrderSigner::new(&pk).unwrap()
    }

    fn test_order() -> PolymarketOrder {
        PolymarketOrder {
            salt: 123456789,
            maker: "0xf39fd6e51aad88f6f4ce6ab8827279cfffb92266".to_string(),
            signer: "0xf39fd6e51aad88f6f4ce6ab8827279cfffb92266".to_string(),
            token_id: Ustr::from(
                "71321045679252212594626385532706912750332728571942532289631379312455583992563",
            ),
            maker_amount: dec!(100000000),
            taker_amount: dec!(50000000),
            expiration: "0".to_string(),
            timestamp: 1_000_000_000_000u64,
            metadata: alloy_primitives::B256::ZERO,
            builder: alloy_primitives::B256::ZERO,
            side: PolymarketOrderSide::Buy,
            signature_type: SignatureType::Eoa,
            signature: String::new(),
        }
    }

    #[rstest]
    fn test_order_typehash_matches_contract() {
        let expected = keccak256(
            "Order(uint256 salt,address maker,address signer,uint256 tokenId,uint256 makerAmount,uint256 takerAmount,uint8 side,uint8 signatureType,uint256 timestamp,bytes32 metadata,bytes32 builder)",
        );
        let order = test_order();
        let eip712_order = build_eip712_order(&order).unwrap();
        assert_eq!(eip712_order.eip712_type_hash(), expected);
    }

    #[rstest]
    fn test_signer_address_derivation() {
        let signer = test_signer();
        // Hardhat account #0
        let expected = Address::from_str("0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266").unwrap();
        assert_eq!(signer.address(), expected);
    }

    #[rstest]
    fn test_sign_order_format() {
        let signer = test_signer();
        let order = test_order();

        let sig = signer.sign_order(&order, false).unwrap();

        assert!(sig.starts_with("0x"));
        assert_eq!(sig.len(), 132); // 0x + r(64) + s(64) + v(2)
    }

    #[rstest]
    fn test_sign_order_deterministic() {
        let signer = test_signer();
        let order = test_order();

        let sig1 = signer.sign_order(&order, false).unwrap();
        let sig2 = signer.sign_order(&order, false).unwrap();
        assert_eq!(sig1, sig2);
    }

    #[rstest]
    fn test_sign_order_neg_risk_differs() {
        let signer = test_signer();
        let order = test_order();

        let sig_normal = signer.sign_order(&order, false).unwrap();
        let sig_neg_risk = signer.sign_order(&order, true).unwrap();
        assert_ne!(sig_normal, sig_neg_risk);
    }

    #[rstest]
    fn test_sign_order_sell_side() {
        let signer = test_signer();
        let mut order = test_order();
        let sig_buy = signer.sign_order(&order, false).unwrap();

        order.side = PolymarketOrderSide::Sell;
        let sig_sell = signer.sign_order(&order, false).unwrap();
        assert_ne!(sig_buy, sig_sell);
    }

    #[rstest]
    fn test_sign_order_different_amounts() {
        let signer = test_signer();
        let mut order = test_order();
        let sig1 = signer.sign_order(&order, false).unwrap();

        order.maker_amount = dec!(200000000);
        let sig2 = signer.sign_order(&order, false).unwrap();
        assert_ne!(sig1, sig2);
    }

    #[rstest]
    fn test_build_eip712_order() {
        let order = test_order();
        let eip712 = build_eip712_order(&order).unwrap();

        assert_eq!(eip712.salt, U256::from(123456789u64));
        assert_eq!(
            eip712.maker,
            Address::from_str("0xf39fd6e51aad88f6f4ce6ab8827279cfffb92266").unwrap()
        );
        assert_eq!(eip712.makerAmount, U256::from(100000000u128));
        assert_eq!(eip712.takerAmount, U256::from(50000000u128));
        assert_eq!(eip712.side, 0); // BUY
        assert_eq!(eip712.signatureType, 0); // EOA
        assert_eq!(eip712.timestamp, U256::from(1_000_000_000_000u64));
        assert_eq!(eip712.metadata, alloy_primitives::B256::ZERO);
        assert_eq!(eip712.builder, alloy_primitives::B256::ZERO);
    }

    #[rstest]
    fn test_decimal_to_u256_integer() {
        let result = decimal_to_u256(dec!(100000000), "test").unwrap();
        assert_eq!(result, U256::from(100000000u128));
    }

    #[rstest]
    fn test_decimal_to_u256_zero() {
        let result = decimal_to_u256(dec!(0), "test").unwrap();
        assert_eq!(result, U256::ZERO);
    }

    #[rstest]
    fn test_decimal_to_u256_rejects_fractional() {
        let result = decimal_to_u256(dec!(100.5), "test");
        assert!(result.is_err());
    }

    #[rstest]
    fn test_decimal_to_u256_rejects_negative() {
        let result = decimal_to_u256(dec!(-1), "test");
        assert!(result.is_err());
    }

    #[rstest]
    fn test_order_side_mapping() {
        assert_eq!(order_side_to_u8(PolymarketOrderSide::Buy), 0);
        assert_eq!(order_side_to_u8(PolymarketOrderSide::Sell), 1);
    }

    #[rstest]
    fn test_contract_addresses_nonzero() {
        assert_ne!(CTF_EXCHANGE, Address::ZERO);
        assert_ne!(NEG_RISK_CTF_EXCHANGE, Address::ZERO);
        assert_ne!(CTF_EXCHANGE, NEG_RISK_CTF_EXCHANGE);
    }

    // -----------------------------------------------------------------------
    // Tests ported from the TS reference (clob-client-v2)
    // -----------------------------------------------------------------------

    // Ported from tests/signing/eip712.test.ts → "buildClobEip712Signature"
    // Private key: Hardhat account #0 (publicly known)
    // Chain: AMOY (80002), timestamp="10000000", nonce=23
    // Expected signature verified by the TS test suite.
    #[rstest]
    fn test_sign_clob_auth_amoy_matches_ts_reference() {
        let pk = EvmPrivateKey::new(TEST_PRIVATE_KEY).unwrap();
        let (_addr, sig) = sign_clob_auth_with_chain_id(&pk, "10000000", 23, 80002).unwrap();
        assert_eq!(
            sig,
            "0xf62319a987514da40e57e2f4d7529f7bac38f0355bd88bb5adbb3768d80de6c1682518e0af677d5260366425f4361e7b70c25ae232aff0ab2331e2b164a1aedc1b"
        );
    }

    // Ported from tests/order-builder/helpers/createOrder.test.ts
    // BUY 0.5 price, 21.04 size, tickSize=0.1 (tick_decimals=1) → makerAmount=10520000, takerAmount=21040000
    // BUY 0.56 price, 21.04 size, tickSize=0.01 (tick_decimals=2) → makerAmount=11782400, takerAmount=21040000
    // SELL 0.5 price, 21.04 size, tickSize=0.1 → makerAmount=21040000, takerAmount=10520000
    // SELL 0.56 price, 21.04 size, tickSize=0.01 → makerAmount=21040000, takerAmount=11782400
    #[rstest]
    #[case(dec!(0.5), dec!(21.04), PolymarketOrderSide::Buy, 1, dec!(10_520_000), dec!(21_040_000))]
    #[case(dec!(0.56), dec!(21.04), PolymarketOrderSide::Buy, 2, dec!(11_782_400), dec!(21_040_000))]
    #[case(dec!(0.056), dec!(21.04), PolymarketOrderSide::Buy, 3, dec!(1_178_240), dec!(21_040_000))]
    #[case(dec!(0.0056), dec!(21.04), PolymarketOrderSide::Buy, 4, dec!(117_824), dec!(21_040_000))]
    #[case(dec!(0.5), dec!(21.04), PolymarketOrderSide::Sell, 1, dec!(21_040_000), dec!(10_520_000))]
    #[case(dec!(0.56), dec!(21.04), PolymarketOrderSide::Sell, 2, dec!(21_040_000), dec!(11_782_400))]
    #[case(dec!(0.056), dec!(21.04), PolymarketOrderSide::Sell, 3, dec!(21_040_000), dec!(1_178_240))]
    #[case(dec!(0.0056), dec!(21.04), PolymarketOrderSide::Sell, 4, dec!(21_040_000), dec!(117_824))]
    fn test_create_order_amounts_match_ts_reference(
        #[case] price: Decimal,
        #[case] quantity: Decimal,
        #[case] side: PolymarketOrderSide,
        #[case] tick_decimals: u32,
        #[case] expected_maker: Decimal,
        #[case] expected_taker: Decimal,
    ) {
        use crate::execution::order_builder::compute_maker_taker_amounts;
        let (maker, taker) = compute_maker_taker_amounts(price, quantity, side, tick_decimals);
        assert_eq!(maker, expected_maker, "makerAmount mismatch");
        assert_eq!(taker, expected_taker, "takerAmount mismatch");
    }

    // Verifies signed orders have non-empty signature, correct maker/signer, and v2 fields.
    // Ported from createOrder.test.ts structural assertions.
    #[rstest]
    fn test_signed_order_v2_fields() {
        use crate::execution::order_builder::compute_maker_taker_amounts;

        let signer = test_signer();
        let eoa = format!("{:#x}", signer.address());
        let (maker_amount, taker_amount) = compute_maker_taker_amounts(
            dec!(0.5),
            dec!(21.04),
            PolymarketOrderSide::Buy,
            1,
        );

        let order = PolymarketOrder {
            salt: 1,
            maker: eoa.clone(),
            signer: eoa.clone(),
            token_id: Ustr::from("123"),
            maker_amount,
            taker_amount,
            expiration: "0".to_string(),
            timestamp: 1_000_000_000_000u64,
            metadata: alloy_primitives::B256::ZERO,
            builder: alloy_primitives::B256::ZERO,
            side: PolymarketOrderSide::Buy,
            signature_type: SignatureType::Eoa,
            signature: String::new(),
        };

        let sig = signer.sign_order_with_chain_id(&order, false, 80002).unwrap();

        assert!(sig.starts_with("0x"), "signature must start with 0x");
        assert_eq!(sig.len(), 132, "signature must be 0x + 64r + 64s + 2v");
        assert_eq!(order.maker, eoa);
        assert_eq!(order.signer, eoa, "EOA: signer must equal maker");
        assert_eq!(order.expiration, "0");
        assert_eq!(order.metadata, alloy_primitives::B256::ZERO);
        assert_eq!(order.builder, alloy_primitives::B256::ZERO);
    }

    #[rstest]
    fn test_sign_order_recoverable() {
        use alloy_primitives::Signature;

        let signer = test_signer();
        let order = test_order();
        let sig_hex = signer.sign_order(&order, false).unwrap();

        let sig_bytes = hex::decode(&sig_hex[2..]).unwrap();
        assert_eq!(sig_bytes.len(), 65);

        let r = U256::from_be_slice(&sig_bytes[..32]);
        let s = U256::from_be_slice(&sig_bytes[32..64]);
        let v = sig_bytes[64];
        let y_parity = v == 28;

        let signature = Signature::new(r, s, y_parity);

        let eip712_order = build_eip712_order(&order).unwrap();
        let domain = eip712_domain! {
            name: DOMAIN_NAME,
            version: DOMAIN_VERSION,
            chain_id: CHAIN_ID,
            verifying_contract: CTF_EXCHANGE,
        };
        let signing_hash = eip712_order.eip712_signing_hash(&domain);

        let recovered = signature
            .recover_address_from_prehash(&signing_hash)
            .unwrap();
        assert_eq!(recovered, signer.address());
    }
}
