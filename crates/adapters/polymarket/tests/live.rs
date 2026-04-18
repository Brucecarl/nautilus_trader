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

//! Live integration tests against the Polymarket CLOB v2 preprod endpoint.
//!
//! All tests are `#[ignore]`d by default and require real credentials:
//!
//!   POLYMARKET_PK          EVM private key (0x-prefixed)
//!   POLYMARKET_FUNDER      Maker/funder address (0x-prefixed)
//!   POLYMARKET_API_KEY     CLOB API key
//!   POLYMARKET_API_SECRET  CLOB API secret (base64)
//!   POLYMARKET_PASSPHRASE  CLOB API passphrase
//!
//! Run with:
//!   cargo test -p nautilus-polymarket --test live -- --ignored --nocapture

use std::sync::Arc;

use serde_json;
use nautilus_polymarket::{
    common::{
        credential::{Credential, EvmPrivateKey},
        enums::{PolymarketOrderSide, PolymarketOrderType, SignatureType},
    },
    execution::order_builder::PolymarketOrderBuilder,
    http::{
        clob::PolymarketClobHttpClient,
        query::GetOrdersParams,
    },
    signing::eip712::OrderSigner,
};


const CLOB_V2_URL: &str = "https://clob-v2.polymarket.com";

// US/Iran nuclear deal 2027 — YES token (from v2 migration doc test markets)
const TEST_TOKEN_ID: &str =
    "102936224134271070189104847090829839924697394514566827387181305960175107677216";

// condition_id for the same market
const TEST_CONDITION_ID: &str =
    "0x182390641d3b1b47cc64274b9da290efd04221c586651ba190880713da6347d9";

fn env(key: &str) -> String {
    std::env::var(key).unwrap_or_else(|_| panic!("env var {key} not set"))
}

fn live_client() -> PolymarketClobHttpClient {
    let api_key = env("POLYMARKET_API_KEY");
    let api_secret = env("POLYMARKET_API_SECRET");
    let passphrase = env("POLYMARKET_PASSPHRASE");
    let funder = env("POLYMARKET_FUNDER");

    let cred = Credential::new(&api_key, &api_secret, passphrase).expect("valid credential");
    PolymarketClobHttpClient::new(cred, funder, Some(CLOB_V2_URL.to_string()), Some(10))
        .expect("valid client")
}

/// Builds a minimal unauthenticated client (no creds) for the L1 derive-api-key call.
fn unauth_client() -> PolymarketClobHttpClient {
    // Credential::new requires non-empty strings; use placeholders — L1 auth doesn't use HMAC.
    let cred = Credential::new("placeholder", "cGxhY2Vob2xkZXI=", "placeholder".to_string())
        .expect("placeholder credential");
    PolymarketClobHttpClient::new(cred, String::new(), Some(CLOB_V2_URL.to_string()), Some(10))
        .expect("valid client")
}

async fn derive_preprod_client(pk: &EvmPrivateKey) -> PolymarketClobHttpClient {
    let signer = OrderSigner::new(pk).expect("valid signer");
    let address = format!("{:#x}", signer.address());

    let creds = unauth_client()
        .derive_api_key(pk, 0)
        .await
        .expect("derive_api_key succeeded");

    println!("derived api_key={} for address={address}", creds.api_key);

    let cred = Credential::new(&creds.api_key, &creds.secret, creds.passphrase)
        .expect("valid derived credential");
    PolymarketClobHttpClient::new(cred, address, Some(CLOB_V2_URL.to_string()), Some(10))
        .expect("valid client")
}

fn live_order_builder() -> PolymarketOrderBuilder {
    let pk_str = env("POLYMARKET_PK");

    let pk = EvmPrivateKey::new(&pk_str).expect("valid private key");
    let signer = OrderSigner::new(&pk).expect("valid signer");
    // For EOA: maker == signer == address derived from POLYMARKET_PK.
    let address = format!("{:#x}", signer.address());

    // The v2 preprod server validates order signatures against Polygon mainnet
    // domain (chain ID 137) — the exchange contract address is the same on both chains.
    PolymarketOrderBuilder::new(signer, address.clone(), address, SignatureType::Eoa)
}

// ---------------------------------------------------------------------------
// Public endpoint — no credentials needed
// ---------------------------------------------------------------------------

/// Verifies the v2 order book endpoint returns valid bids/asks.
#[tokio::test]
#[ignore = "live: requires network access to clob-v2.polymarket.com"]
async fn live_get_book_returns_bids_and_asks() {
    let client = live_client();
    let book = client.get_book(TEST_TOKEN_ID).await.unwrap();

    println!("bids: {}, asks: {}", book.bids.len(), book.asks.len());
    assert!(
        !book.bids.is_empty() || !book.asks.is_empty(),
        "expected at least one side to have levels"
    );
    if let Some(b) = book.bids.first() {
        println!("best bid: {} @ {}", b.size, b.price);
        b.price.parse::<f64>().expect("bid price is decimal");
    }
    if let Some(a) = book.asks.first() {
        println!("best ask: {} @ {}", a.size, a.price);
        a.price.parse::<f64>().expect("ask price is decimal");
    }
}

// ---------------------------------------------------------------------------
// Authenticated endpoints
// ---------------------------------------------------------------------------

/// Derives preprod API credentials from POLYMARKET_PK via the L1 EIP-712 auth flow.
/// Prints the api_key, secret, and passphrase for use as POLYMARKET_API_KEY etc.
#[tokio::test]
#[ignore = "live: requires POLYMARKET_PK env var and network access to clob-v2.polymarket.com"]
async fn live_derive_api_key() {
    let pk = EvmPrivateKey::new(&env("POLYMARKET_PK")).expect("valid private key");
    let signer = OrderSigner::new(&pk).expect("valid signer");
    let address = format!("{:#x}", signer.address());

    let creds = unauth_client()
        .derive_api_key(&pk, 0)
        .await
        .expect("derive_api_key succeeded");

    println!("address:    {address}");
    println!("api_key:    {}", creds.api_key);
    println!("secret:     {}", creds.secret);
    println!("passphrase: {}", creds.passphrase);

    assert!(!creds.api_key.is_empty());
    assert!(!creds.secret.is_empty());
    assert!(!creds.passphrase.is_empty());
}

/// Signs a limit order locally and submits it to the v2 preprod server,
/// then verifies it appears in open orders, then cancels it.
/// This is the "full order lifecycle" the migration checklist requires.
/// Derives preprod credentials automatically from POLYMARKET_PK.
#[tokio::test]
#[ignore = "live: requires POLYMARKET_PK env var and funded preprod account on clob-v2.polymarket.com"]
async fn live_order_lifecycle_submit_verify_cancel() {
    let pk = EvmPrivateKey::new(&env("POLYMARKET_PK")).expect("valid private key");
    let client = derive_preprod_client(&pk).await;
    let builder = Arc::new(live_order_builder());

    // Use a very low price so the order won't fill immediately
    let price = rust_decimal_macros::dec!(0.02);
    let quantity = rust_decimal_macros::dec!(5); // minimum order size

    let order = builder
        .build_limit_order(
            TEST_TOKEN_ID,
            PolymarketOrderSide::Buy,
            price,
            quantity,
            "0", // no expiration
            false,
            2, // 0.01 tick → 2 decimal places
        )
        .expect("built order");

    println!("order payload: {}", serde_json::to_string_pretty(&order).unwrap());

    // 1. Submit
    let response = client
        .post_order(&order, PolymarketOrderType::GTC, false)
        .await
        .expect("post_order succeeded");

    assert!(response.success, "expected success=true, got: {:?}", response);
    let order_id = response.order_id.expect("order_id must be present");
    println!("order accepted: id={order_id}");

    // 2. Verify it appears in open orders
    let open = client
        .get_orders(GetOrdersParams {
            asset_id: Some(TEST_TOKEN_ID.to_string()),
            ..Default::default()
        })
        .await
        .expect("get_orders succeeded");

    let found = open.iter().any(|o| o.id == order_id);
    assert!(found, "submitted order {order_id} not found in open orders");
    println!("order confirmed in open orders");

    // 3. Cancel it
    let cancel = client
        .cancel_order(&order_id)
        .await
        .expect("cancel_order succeeded");

    println!("cancel response: {:?}", cancel);
    assert!(
        cancel.canceled.contains(&order_id),
        "expected order_id in canceled list"
    );
    println!("order lifecycle complete: submit → verify → cancel ✓");
}

/// Verifies that /clob-market-info returns valid tick/order-size fields.
/// This endpoint is active after the April 22 cutover.
#[tokio::test]
#[ignore = "live: requires network access to clob-v2.polymarket.com (endpoint active after April 22 cutover)"]
async fn live_get_clob_market_info_valid_fields() {
    let client = live_client();
    let info = client
        .get_clob_market_info(TEST_CONDITION_ID)
        .await
        .unwrap();

    println!("mts={} mos={}", info.mts, info.mos);
    assert!(!info.mts.is_empty(), "mts should be non-empty");
    assert!(!info.mos.is_empty(), "mos should be non-empty");
    info.mts.parse::<f64>().expect("mts is a decimal");
    info.mos.parse::<f64>().expect("mos is a decimal");
}
