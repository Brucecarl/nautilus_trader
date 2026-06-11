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

//! Provides the HTTP client for the Polymarket CLOB REST API.

use std::sync::Arc;
use std::{collections::HashMap, result::Result as StdResult, str::from_utf8, time::SystemTime};

use anyhow::{Context, bail};
use futures_util::{StreamExt, stream};
use nautilus_core::{
    consts::NAUTILUS_USER_AGENT,
    time::{AtomicTime, get_atomic_clock_realtime},
};
use nautilus_model::data::BarSpecification;
use nautilus_model::{
    data::bar::{Bar, BarType},
    data::BookOrder,
    enums::{BarAggregation, BookType, OrderSide},
    identifiers::InstrumentId,
    orderbook::OrderBook,
    types::{Price, Quantity},
};
use nautilus_network::http::{HttpClient, HttpClientError, Method, USER_AGENT};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize, de::DeserializeOwned};

use crate::common::models::resolve_token_id;
use crate::{
    common::{
        consts::CHAIN_ID,
        credential::Credential,
        enums::PolymarketOrderType,
        urls::clob_http_url,
    },
    http::{
        error::{Error, Result},
        models::{
            ClobBookResponse, ClobMarketInfo, PolymarketOpenOrder, PolymarketOrder, PolymarketTradeReport, TickSizeResponse
        },
        query::{
            BalanceAllowance, BatchCancelResponse, CancelMarketOrdersParams, CancelResponse,
            DerivedCredential, GetBalanceAllowanceParams, GetOrdersParams, GetTradesParams,
            OrderResponse, PaginatedResponse,
        },
        rate_limits::POLYMARKET_CLOB_REST_QUOTA,
    },
    signing::eip712::{OrderSigner, sign_clob_auth_with_chain_id},
    websocket::parse::{parse_price, parse_quantity},
};

const CURSOR_START: &str = "MA==";
const CURSOR_END: &str = "LTE=";

const PATH_ORDERS: &str = "/data/orders";
const PATH_TRADES: &str = "/data/trades";
const PATH_BALANCE_ALLOWANCE: &str = "/balance-allowance";
const PATH_POST_ORDER: &str = "/order";
const PATH_POST_ORDERS: &str = "/orders";
const PATH_CANCEL_ALL: &str = "/cancel-all";
const PATH_CANCEL_MARKET_ORDERS: &str = "/cancel-market-orders";
const CONCURRENCY:usize=4;

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct PostOrderBody<'a> {
    order: &'a PolymarketOrder,
    owner: &'a str,
    order_type: PolymarketOrderType,
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    post_only: bool,
}

#[derive(Serialize)]
struct CancelOrderBody<'a> {
    #[serde(rename = "orderID")]
    order_id: &'a str,
}

/// Request body for `POST /batch-prices-history`.
#[derive(Serialize)]
struct BatchPricesHistoryRequestBody<'a> {
    markets: &'a [String],
    #[serde(skip_serializing_if = "Option::is_none")]
    start_ts: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    end_ts: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    interval: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    fidelity: Option<u64>,
}

/// Response wrapper for `POST /batch-prices-history`.
#[derive(Deserialize)]
struct BatchPricesHistoryResponse {
    history: HashMap<String, Vec<PricePoint>>,
}

/// Price history aggregation interval for the Data API batch price history endpoint.
///
/// Defaults to 1 day when not specified.
#[derive(Clone, Debug, strum::Display)]
enum PriceInterval {
    #[strum(serialize = "max")]
    Max,
    #[strum(serialize = "all")]
    All,
    /// 1 month
    #[strum(serialize = "1m")]
    M1,
    /// 1 week
    #[strum(serialize = "1w")]
    W1,
    /// 1 day
    #[strum(serialize = "1d")]
    D1,
    /// 6 hours
    #[strum(serialize = "6h")]
    H6,
    /// 1 hour
    #[strum(serialize = "1h")]
    H1,
}

impl PriceInterval {
    // Accuracy of the data expressed in minutes. Default is 1 minute.
    pub fn default_fidelity(&self) -> u64 {
        match self {
            PriceInterval::Max => 15,
            PriceInterval::All => 15,
            PriceInterval::M1 => 15,
            PriceInterval::W1 => 5,
            PriceInterval::D1 => 5,
            PriceInterval::H6 => 1,
            PriceInterval::H1 => 1,
        }
    }
}

/// A single price point from the Data API batch price history endpoint.
///
/// References: <https://docs.polymarket.com/api-reference/markets/get-batch-prices-history>
#[derive(Clone, Debug, Deserialize)]
struct PricePoint {
    /// Unix timestamp in seconds.
    #[serde(rename = "t")]
    pub timestamp: i64,
    /// Price at this timestamp.
    #[serde(rename = "p")]
    pub price: f64,
}

/// Provides an authenticated HTTP client for the Polymarket CLOB REST API.
///
/// Handles HTTP transport, L2 HMAC-SHA256 auth signing, pagination, and raw
/// API calls that closely match Polymarket endpoint specifications.
/// Credential is always present: the CLOB API requires authentication.
#[derive(Debug, Clone)]
pub struct PolymarketClobHttpClient {
    client: HttpClient,
    base_url: String,
    credential: Credential,
    address: String,
    clock: &'static AtomicTime,
}

impl PolymarketClobHttpClient {
    /// Creates a new authenticated [`PolymarketClobHttpClient`].
    ///
    /// # Errors
    ///
    /// Returns an error if the HTTP client cannot be created.
    pub fn new(
        credential: Credential,
        address: String,
        base_url: Option<String>,
        timeout_secs: Option<u64>,
    ) -> StdResult<Self, HttpClientError> {
        Ok(Self {
            client: HttpClient::new(
                Self::default_headers(),
                vec![],
                vec![],
                Some(*POLYMARKET_CLOB_REST_QUOTA),
                timeout_secs,
                None,
            )?,
            base_url: base_url
                .unwrap_or_else(|| clob_http_url().to_string())
                .trim_end_matches('/')
                .to_string(),
            credential,
            address,
            clock: get_atomic_clock_realtime(),
        })
    }

    fn default_headers() -> HashMap<String, String> {
        HashMap::from([
            (USER_AGENT.to_string(), NAUTILUS_USER_AGENT.to_string()),
            ("Content-Type".to_string(), "application/json".to_string()),
        ])
    }

    fn url(&self, path: &str) -> String {
        format!("{}{path}", self.base_url)
    }

    fn timestamp(&self) -> String {
        (self.clock.get_time_ns().as_u64() / 1_000_000_000).to_string()
    }

    fn l1_auth_headers(
        &self,
        private_key: &crate::common::credential::EvmPrivateKey,
        nonce: u64,
    ) -> Result<HashMap<String, String>> {
        let timestamp = self.timestamp();
        // L1 ClobAuth always signs against Polygon mainnet (137) regardless of order chain.
        let (address, signature) =
            sign_clob_auth_with_chain_id(private_key, &timestamp, nonce, CHAIN_ID)?;
        Ok(HashMap::from([
            ("POLY_ADDRESS".to_string(), address),
            ("POLY_SIGNATURE".to_string(), signature),
            ("POLY_TIMESTAMP".to_string(), timestamp),
            ("POLY_NONCE".to_string(), nonce.to_string()),
        ]))
    }

    fn auth_headers(&self, method: &str, path: &str, body: &str) -> HashMap<String, String> {
        let timestamp = self.timestamp();
        let signature = self.credential.sign(&timestamp, method, path, body);

        HashMap::from([
            ("POLY_ADDRESS".to_string(), self.address.clone()),
            ("POLY_SIGNATURE".to_string(), signature),
            ("POLY_TIMESTAMP".to_string(), timestamp),
            (
                "POLY_API_KEY".to_string(),
                self.credential.api_key().to_string(),
            ),
            (
                "POLY_PASSPHRASE".to_string(),
                self.credential.passphrase().to_string(),
            ),
        ])
    }

    async fn send_get<P: Serialize, T: DeserializeOwned>(
        &self,
        path: &str,
        params: Option<&P>,
        auth: bool,
    ) -> Result<T> {
        let headers = if auth {
            Some(self.auth_headers("GET", path, ""))
        } else {
            None
        };
        let url = self.url(path);
        let response = self
            .client
            .request_with_params(Method::GET, url, params, headers, None, None, None)
            .await
            .map_err(Error::from_http_client)?;

        if response.status.is_success() {
            serde_json::from_slice(&response.body).map_err(Error::Serde)
        } else {
            Err(Error::from_status_code(
                response.status.as_u16(),
                &response.body,
            ))
        }
    }

    /// Like [`send_get`] but returns `Ok(None)` for empty or `null` response bodies
    /// instead of a serde deserialization error.
    async fn send_get_optional<P: Serialize, T: DeserializeOwned>(
        &self,
        path: &str,
        params: Option<&P>,
        auth: bool,
    ) -> Result<Option<T>> {
        let headers = if auth {
            Some(self.auth_headers("GET", path, ""))
        } else {
            None
        };
        let url = self.url(path);
        let response = self
            .client
            .request_with_params(Method::GET, url, params, headers, None, None, None)
            .await
            .map_err(Error::from_http_client)?;

        if response.status.is_success() {
            if response.body.is_empty() || response.body.as_ref() == b"null" {
                Ok(None)
            } else {
                serde_json::from_slice(&response.body)
                    .map(Some)
                    .map_err(Error::Serde)
            }
        } else {
            Err(Error::from_status_code(
                response.status.as_u16(),
                &response.body,
            ))
        }
    }

    async fn send_post<T: DeserializeOwned>(&self, path: &str, body_bytes: Vec<u8>) -> Result<T> {
        let body_str =
            from_utf8(&body_bytes).map_err(|e| Error::decode(format!("UTF-8 error: {e}")))?;
        let headers = Some(self.auth_headers("POST", path, body_str));
        let url = self.url(path);
        let response = self
            .client
            .request(
                Method::POST,
                url,
                None,
                headers,
                Some(body_bytes),
                None,
                None,
            )
            .await
            .map_err(Error::from_http_client)?;

        if response.status.is_success() {
            serde_json::from_slice(&response.body).map_err(Error::Serde)
        } else {
            Err(Error::from_status_code(
                response.status.as_u16(),
                &response.body,
            ))
        }
    }

    async fn send_delete<T: DeserializeOwned>(
        &self,
        path: &str,
        body_bytes: Option<Vec<u8>>,
    ) -> Result<T> {
        let body_str = body_bytes
            .as_deref()
            .map(|b| from_utf8(b).map_err(|e| Error::decode(format!("UTF-8 error: {e}"))))
            .transpose()?
            .unwrap_or("");
        let headers = Some(self.auth_headers("DELETE", path, body_str));
        let url = self.url(path);
        let response = self
            .client
            .request(Method::DELETE, url, None, headers, body_bytes, None, None)
            .await
            .map_err(Error::from_http_client)?;

        if response.status.is_success() {
            serde_json::from_slice(&response.body).map_err(Error::Serde)
        } else {
            Err(Error::from_status_code(
                response.status.as_u16(),
                &response.body,
            ))
        }
    }

    /// Fetches all open orders matching the given parameters (auto-paginated).
    pub async fn get_orders(
        &self,
        mut params: GetOrdersParams,
    ) -> Result<Vec<PolymarketOpenOrder>> {
        if params.next_cursor.is_none() {
            params.next_cursor = Some(CURSOR_START.to_string());
        }
        let mut all = Vec::new();
        loop {
            let page: PaginatedResponse<PolymarketOpenOrder> =
                self.send_get(PATH_ORDERS, Some(&params), true).await?;
            all.extend(page.data);
            if page.next_cursor == CURSOR_END {
                break;
            }
            params.next_cursor = Some(page.next_cursor);
        }
        Ok(all)
    }

    /// Fetches a single open order by ID, returning `None` for empty/null responses.
    pub async fn get_order_optional(&self, order_id: &str) -> Result<Option<PolymarketOpenOrder>> {
        let path = format!("/data/order/{order_id}");
        self.send_get_optional::<(), _>(&path, None::<&()>, true)
            .await
    }

    /// Fetches a single open order by ID.
    ///
    /// Returns an error if the order is not found (empty/null response).
    pub async fn get_order(&self, order_id: &str) -> Result<PolymarketOpenOrder> {
        self.get_order_optional(order_id)
            .await?
            .ok_or_else(|| Error::decode(format!("Order {order_id} not found (empty response)")))
    }

    /// Fetches all trades matching the given parameters (auto-paginated).
    pub async fn get_trades(
        &self,
        mut params: GetTradesParams,
    ) -> Result<Vec<PolymarketTradeReport>> {
        if params.next_cursor.is_none() {
            params.next_cursor = Some(CURSOR_START.to_string());
        }
        let mut all = Vec::new();
        loop {
            let page: PaginatedResponse<PolymarketTradeReport> =
                self.send_get(PATH_TRADES, Some(&params), true).await?;
            all.extend(page.data);
            if page.next_cursor == CURSOR_END {
                break;
            }
            params.next_cursor = Some(page.next_cursor);
        }
        Ok(all)
    }

    /// Fetches balance and allowance for the given parameters.
    pub async fn get_balance_allowance(
        &self,
        params: GetBalanceAllowanceParams,
    ) -> Result<BalanceAllowance> {
        let headers = Some(self.auth_headers("GET", PATH_BALANCE_ALLOWANCE, ""));
        let url = self.url(PATH_BALANCE_ALLOWANCE);
        let response = self
            .client
            .request_with_params(Method::GET, url, Some(&params), headers, None, None, None)
            .await
            .map_err(Error::from_http_client)?;

        if response.status.is_success() {
            serde_json::from_slice(&response.body).map_err(Error::Serde)
        } else {
            Err(Error::from_status_code(
                response.status.as_u16(),
                &response.body,
            ))
        }
    }

    /// Submits a single signed order to the exchange.
    pub async fn post_order(
        &self,
        order: &PolymarketOrder,
        order_type: PolymarketOrderType,
        post_only: bool,
    ) -> Result<OrderResponse> {
        let owner = self.credential.api_key().to_string();
        let body = PostOrderBody {
            order,
            owner: &owner,
            order_type,
            post_only,
        };
        let body_bytes = serde_json::to_vec(&body).map_err(Error::Serde)?;
        self.send_post(PATH_POST_ORDER, body_bytes).await
    }

    /// Submits a batch of signed orders to the exchange.
    ///
    /// Each entry is `(order, order_type, post_only)`.
    pub async fn post_orders(
        &self,
        orders: &[(&PolymarketOrder, PolymarketOrderType, bool)],
    ) -> Result<Vec<OrderResponse>> {
        let owner = self.credential.api_key().to_string();
        let entries: Vec<PostOrderBody<'_>> = orders
            .iter()
            .map(|(order, order_type, post_only)| PostOrderBody {
                order,
                owner: &owner,
                order_type: *order_type,
                post_only: *post_only,
            })
            .collect();
        let body_bytes = serde_json::to_vec(&entries).map_err(Error::Serde)?;
        self.send_post(PATH_POST_ORDERS, body_bytes).await
    }

    /// Cancels a single order by ID.
    pub async fn cancel_order(&self, order_id: &str) -> Result<CancelResponse> {
        let body = CancelOrderBody { order_id };
        let body_bytes = serde_json::to_vec(&body).map_err(Error::Serde)?;
        self.send_delete("/order", Some(body_bytes)).await
    }

    /// Cancels multiple orders by ID.
    pub async fn cancel_orders(&self, order_ids: &[&str]) -> Result<BatchCancelResponse> {
        let body_bytes = serde_json::to_vec(order_ids).map_err(Error::Serde)?;
        self.send_delete("/orders", Some(body_bytes)).await
    }

    /// Cancels all open orders.
    pub async fn cancel_all(&self) -> Result<BatchCancelResponse> {
        self.send_delete(PATH_CANCEL_ALL, None).await
    }

    /// Cancels all orders for a specific market.
    pub async fn cancel_market_orders(
        &self,
        params: CancelMarketOrdersParams,
    ) -> Result<BatchCancelResponse> {
        let body_bytes = serde_json::to_vec(&params).map_err(Error::Serde)?;
        self.send_delete(PATH_CANCEL_MARKET_ORDERS, Some(body_bytes))
            .await
    }

    /// Fetches the tick size for a token from the CLOB API.
    pub async fn get_tick_size(&self, token_id: &str) -> Result<TickSizeResponse> {
        let params = [("token_id", token_id)];
        self.send_get("/tick-size", Some(&params), false).await
    }

    /// Fetches combined market info (tick size and minimum order size) for a condition ID.
    ///
    /// Replaces the separate `/tick-size` and `/fee-rate` calls in CLOB v2.
    pub async fn get_clob_market_info(&self, condition_id: &str) -> Result<ClobMarketInfo> {
        let params = [("condition_id", condition_id)];
        self.send_get("/clob-market-info", Some(&params), false).await
    }

    /// Derives API credentials from a private key via the L1 EIP-712 auth flow.
    ///
    /// Calls `GET /auth/derive-api-key` with L1 headers signed by `private_key`.
    /// The L1 ClobAuth signature always uses Polygon mainnet (chain ID 137).
    /// Returns `(api_key, secret, passphrase)` ready for use with [`Credential`].
    pub async fn derive_api_key(
        &self,
        private_key: &crate::common::credential::EvmPrivateKey,
        nonce: u64,
    ) -> Result<DerivedCredential> {
        let headers = self.l1_auth_headers(private_key, nonce)?;
        let url = self.url("/auth/derive-api-key");
        let response = self
            .client
            .request(Method::GET, url, None, Some(headers), None, None, None)
            .await
            .map_err(Error::from_http_client)?;

        if response.status.is_success() {
            serde_json::from_slice(&response.body).map_err(Error::Serde)
        } else {
            Err(Error::from_status_code(
                response.status.as_u16(),
                &response.body,
            ))
        }
    }

    /// Fetches the order book for a token from the CLOB API (public endpoint).
    pub async fn get_book(&self, token_id: &str) -> Result<ClobBookResponse> {
        let params = [("token_id", token_id)];
        self.send_get("/book", Some(&params), false).await
    }
}

/// Provides an unauthenticated HTTP client for public CLOB endpoints.
///
/// Unlike [`PolymarketClobHttpClient`], this client does not require credentials
/// and is suitable for the data client which only needs public market data.
#[derive(Debug, Clone)]
pub struct PolymarketClobPublicClient {
    client: HttpClient,
    base_url: String,
}

impl PolymarketClobPublicClient {
    /// Creates a new [`PolymarketClobPublicClient`].
    ///
    /// # Errors
    ///
    /// Returns an error if the HTTP client cannot be created.
    pub fn new(
        base_url: Option<String>,
        timeout_secs: Option<u64>,
    ) -> StdResult<Self, HttpClientError> {
        Ok(Self {
            client: HttpClient::new(
                HashMap::from([
                    (USER_AGENT.to_string(), NAUTILUS_USER_AGENT.to_string()),
                    ("Content-Type".to_string(), "application/json".to_string()),
                ]),
                vec![],
                vec![],
                Some(*POLYMARKET_CLOB_REST_QUOTA),
                timeout_secs,
                None,
            )?,
            base_url: base_url
                .unwrap_or_else(|| clob_http_url().to_string())
                .trim_end_matches('/')
                .to_string(),
        })
    }

    /// Fetches the order book for a token from the CLOB API.
    pub async fn get_book(&self, token_id: &str) -> Result<ClobBookResponse> {
        let params = [("token_id", token_id)];
        let url = format!("{}/book", self.base_url);
        let response = self
            .client
            .request_with_params(Method::GET, url, Some(&params), None, None, None, None)
            .await
            .map_err(Error::from_http_client)?;

        if response.status.is_success() {
            serde_json::from_slice(&response.body).map_err(Error::Serde)
        } else {
            Err(Error::from_status_code(
                response.status.as_u16(),
                &response.body,
            ))
        }
    }

    /// Requests an order book snapshot and builds an [`OrderBook`].
    pub async fn request_book_snapshot(
        &self,
        instrument_id: InstrumentId,
        token_id: &str,
        price_precision: u8,
        size_precision: u8,
    ) -> anyhow::Result<OrderBook> {
        let resp = self
            .get_book(token_id)
            .await
            .map_err(|e| anyhow::anyhow!(e))?;

        let mut book = OrderBook::new(instrument_id, BookType::L2_MBP);

        for (i, level) in resp.bids.iter().enumerate() {
            let price = parse_price(&level.price, price_precision)?;
            let size = parse_quantity(&level.size, size_precision)?;
            let order = BookOrder::new(OrderSide::Buy, price, size, i as u64);
            book.add(order, 0, i as u64, Default::default());
        }

        let bids_len = resp.bids.len();
        for (i, level) in resp.asks.iter().enumerate() {
            let price = parse_price(&level.price, price_precision)?;
            let size = parse_quantity(&level.size, size_precision)?;
            let order = BookOrder::new(OrderSide::Sell, price, size, (bids_len + i) as u64);
            book.add(order, 0, (bids_len + i) as u64, Default::default());
        }

        log::info!(
            "Fetched order book for {} with {} bids and {} asks",
            instrument_id,
            resp.bids.len(),
            resp.asks.len(),
        );

        Ok(book)
    }

    /// Fetches batch price history for one or more markets from the CLOB API.
    ///
    /// Makes a `POST /batch-prices-history` request with the given market condition IDs
    /// and optional time range, interval, and fidelity parameters.
    /// Only `markets` is required; the API returns all available data when start/end
    /// timestamps are omitted. `interval` defaults to 1 day if `None`.
    ///
    /// References: <https://docs.polymarket.com/api-reference/markets/get-batch-prices-history>
    async fn price_history(
        &self,
        markets: &[String],
        start_ts: Option<u64>,
        end_ts: Option<u64>,
        interval: Option<PriceInterval>,//set this to None to get all data in start_ts and end_ts
        fidelity:Option<u64>,//1min,5min,15,min
    ) -> anyhow::Result<HashMap<String, Vec<PricePoint>>> {
        if start_ts.is_none()&&end_ts.is_none()&&interval.is_none(){
            bail!("one of start_ts|end_ts|interval should be provided");
        }

        let fidelity=fidelity.unwrap_or(interval.as_ref().map(|v|v.default_fidelity()).unwrap_or(1));

        let body = BatchPricesHistoryRequestBody {
            markets,
            start_ts,
            end_ts,
            interval:interval.map(|v|v.to_string()),
            fidelity:Some(fidelity),
        };
        let body_bytes = serde_json::to_vec(&body).map_err(Error::Serde)?;

        let url = format!("{}/batch-prices-history", self.base_url);
        let response = self
            .client
            .request(Method::POST, url, None, None, Some(body_bytes), None, None)
            .await
            .map_err(Error::from_http_client)?;

        if response.status.is_success() {
            let resp: BatchPricesHistoryResponse =
                serde_json::from_slice(&response.body).map_err(Error::Serde)?;
            Ok(resp.history)
        } else {
            Err(Error::from_status_code(
                response.status.as_u16(),
                &response.body,
            )).context("response error:")
        }
    }

    
    pub async fn request_bars(
        &self,
        instrument_ids: &[InstrumentId],
        spec:BarSpecification,
        start: Option<DateTime<Utc>>,
        end: Option<DateTime<Utc>>,
    ) -> anyhow::Result<HashMap<String, Vec<Bar>>>{
        const MAX_BATCH: usize = 20;
        let me = Arc::new(self.clone());
        let chunks: Vec<Vec<_>> = instrument_ids.chunks(MAX_BATCH).map(|c| c.to_vec()).collect();
        let results: Vec<anyhow::Result<HashMap<String, Vec<Bar>>>> = stream::iter(
            chunks.into_iter().map(|chunk| {
                let me = Arc::clone(&me);
                async move { me.request_bars_chunk(&chunk, spec, start, end).await }
            }),
        )
        .buffer_unordered(CONCURRENCY)
        .collect()
        .await;

        let mut mm = HashMap::with_capacity(instrument_ids.len());
        for res in results {
            mm.extend(res?);
        }
        Ok(mm)
    }

    /// Fetches historical bars (OHLCV) using the batch price history endpoint.
    ///
    /// Accepts up to 20 token IDs in a single call (Polymarket API limit).
    /// Uses `interval=all` to fetch raw price points from the full requested
    /// time range, sub-sampled at `fidelity` (minutes). Points are then grouped
    /// into bar windows aligned to the bar specification and aggregated into
    /// OHLC bars. Volume is not available from Polymarket and set to zero.
    /// Only time-based aggregations (Minute, Hour, Day) are supported.
    pub async fn request_bars_chunk(
        &self,
        instrument_ids: &[InstrumentId],
        spec:BarSpecification,
        start: Option<DateTime<Utc>>,
        end: Option<DateTime<Utc>>,
    ) -> anyhow::Result<HashMap<String, Vec<Bar>>> {
        if instrument_ids.is_empty() {
            return Ok(HashMap::new());
        }
        let token_ids=instrument_ids.iter().map(|id|resolve_token_id(id)).collect::<Vec<_>>();

        // let spec = bar_type.spec();
        // Determine sub-sampling fidelity and bar-window alignment
        let (fidelity, window_secs) = match spec.aggregation {
            BarAggregation::Minute => (1, (spec.step.get() * 60) as u64),
            BarAggregation::Hour => (10, (spec.step.get() * 3600) as u64),
            BarAggregation::Day => (60, (spec.step.get() * 86400) as u64),  // hourly sub-sampling
            _ => {
                log::warn!(
                    "Unsupported bar aggregation {:?} for Polymarket price history",
                    spec.aggregation
                );
                return Ok(HashMap::new());
            }
        };

        let start_ts = start.map(|t| t.timestamp() as u64);
        let end_ts = end.map(|t| t.timestamp() as u64);
        const MAX_BATCH: usize = 20;

        // Batch API calls (max 20 per request)
        let mut history: HashMap<String, Vec<PricePoint>> = HashMap::new();
        for chunk in token_ids.chunks(MAX_BATCH) {
            let chunk_result = self
                .price_history(chunk, start_ts, end_ts, None, Some(fidelity))
                .await?;
            history.extend(chunk_result);
        }

        let ts_init = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos() as u64;

        let mut result: HashMap<String, Vec<Bar>> = HashMap::new();

        for (i,token_id) in token_ids.iter().enumerate() {
            let points = match history.get(token_id) {
                Some(p) if !p.is_empty() => p,
                _ => continue,
            };

            let mut bars: Vec<Bar> = Vec::new();
            let mut window_points: Vec<f64> = Vec::new();
            let mut current_window: Option<u64> = None;
            let bar_type=BarType::Standard { instrument_id:instrument_ids[i], spec, aggregation_source: nautilus_model::enums::AggregationSource::External };

            for point in points {
                let ts_secs = point.timestamp as u64;
                let bar_start = (ts_secs / window_secs) * window_secs;

                match current_window {
                    Some(w) if w == bar_start => {
                        window_points.push(point.price);
                    }
                    Some(w) => {
                        aggregate_and_push(
                            &mut bars, &bar_type, &window_points, 4,
                            2, w, ts_init,
                        );
                        window_points.clear();
                        window_points.push(point.price);
                        current_window = Some(bar_start);
                    }
                    None => {
                        window_points.push(point.price);
                        current_window = Some(bar_start);
                    }
                }
            }

            if let Some(w) = current_window {
                aggregate_and_push(
                    &mut bars, &bar_type, &window_points, 4,
                    2, w, ts_init,
                );
            }

            result.insert(token_id.clone(), bars);
        }

        Ok(result)
    }
}

/// Aggregate a bar window's price points into an OHLC bar and push to `bars`.
/// Respects `limit` by skipping the push when already reached.
fn aggregate_and_push(
    bars: &mut Vec<Bar>,
    bar_type: &BarType,
    window_points: &[f64],
    price_precision: u8,
    size_precision: u8,
    window_start_secs: u64,
    ts_init: u64,
) {
    if window_points.is_empty() {
        return;
    }

    let open = window_points[0];
    let close = *window_points.last().unwrap();
    let high = window_points.iter().cloned().fold(f64::NEG_INFINITY, f64::max);
    let low = window_points.iter().cloned().fold(f64::INFINITY, f64::min);

    let ts_event_ns = window_start_secs * 1_000_000_000;

    bars.push(Bar::new(
        *bar_type,
        Price::new(open, price_precision),
        Price::new(high, price_precision),
        Price::new(low, price_precision),
        Price::new(close, price_precision),
        Quantity::zero(size_precision),
        ts_event_ns.into(),
        ts_init.into(),
    ));
}

#[cfg(test)]
mod tests {
    use chrono::Utc;
use nautilus_model::{
        enums::{BookType, OrderSide},
        identifiers::InstrumentId,
        types::{Price, Quantity},
    };
    use rstest::rstest;

    use super::*;
    use crate::http::models::{ClobBookLevel, ClobBookResponse};

    fn build_book_from_response(resp: &ClobBookResponse) -> OrderBook {
        let instrument_id = InstrumentId::from("TEST.POLYMARKET");
        let price_precision = 2u8;
        let size_precision = 2u8;
        let mut book = OrderBook::new(instrument_id, BookType::L2_MBP);

        for (i, level) in resp.bids.iter().enumerate() {
            let price = parse_price(&level.price, price_precision).unwrap();
            let size = parse_quantity(&level.size, size_precision).unwrap();
            let order = BookOrder::new(OrderSide::Buy, price, size, i as u64);
            book.add(order, 0, i as u64, Default::default());
        }

        let bids_len = resp.bids.len();
        for (i, level) in resp.asks.iter().enumerate() {
            let price = parse_price(&level.price, price_precision).unwrap();
            let size = parse_quantity(&level.size, size_precision).unwrap();
            let order = BookOrder::new(OrderSide::Sell, price, size, (bids_len + i) as u64);
            book.add(order, 0, (bids_len + i) as u64, Default::default());
        }

        book
    }

    #[rstest]
    fn test_build_order_book_from_clob_response() {
        let resp = ClobBookResponse {
            bids: vec![
                ClobBookLevel {
                    price: "0.48".to_string(),
                    size: "100.00".to_string(),
                },
                ClobBookLevel {
                    price: "0.49".to_string(),
                    size: "200.00".to_string(),
                },
                ClobBookLevel {
                    price: "0.50".to_string(),
                    size: "150.00".to_string(),
                },
            ],
            asks: vec![
                ClobBookLevel {
                    price: "0.51".to_string(),
                    size: "120.00".to_string(),
                },
                ClobBookLevel {
                    price: "0.52".to_string(),
                    size: "180.00".to_string(),
                },
            ],
        };

        let book = build_book_from_response(&resp);

        assert_eq!(book.instrument_id, InstrumentId::from("TEST.POLYMARKET"));
        assert_eq!(book.book_type, BookType::L2_MBP);
        assert_eq!(book.best_bid_price(), Some(Price::from("0.50")));
        assert_eq!(book.best_ask_price(), Some(Price::from("0.51")));
        assert_eq!(book.best_bid_size(), Some(Quantity::from("150.00")));
        assert_eq!(book.best_ask_size(), Some(Quantity::from("120.00")));
        assert_eq!(book.bids(None).count(), 3);
        assert_eq!(book.asks(None).count(), 2);
    }

    #[rstest]
    fn test_build_order_book_empty_response() {
        let resp = ClobBookResponse {
            bids: vec![],
            asks: vec![],
        };

        let book = build_book_from_response(&resp);

        assert!(book.best_bid_price().is_none());
        assert!(book.best_ask_price().is_none());
    }
    #[tokio::test]
    #[ignore = "connect clob"]
    async fn test_price_history(){
        let client=PolymarketClobPublicClient::new(None, None).unwrap();
        let now = Utc::now();
        let start = now - chrono::Duration::hours(1);
        let history=client.price_history(&["7773690994834111725742505316101987766894598058473643503939677008623849288002".to_string()], Some(start.timestamp() as u64), Some(now.timestamp() as u64), None, Some(30)).await.unwrap();
        let res=history.get("7773690994834111725742505316101987766894598058473643503939677008623849288002");
        if let Some(list)=res{
            println!("{}={:?}",list.len(),list);
        }
    }

    #[tokio::test]
    #[ignore = "connect clob"]
    async fn test_request_bars() {
        use nautilus_model::{
            data::bar::BarSpecification,
            enums::{PriceType},
        };

        let client = PolymarketClobPublicClient::new(None, None).unwrap();
        let instrument_id = InstrumentId::from("0x785df65c37d72ac79b34bd8956811c8569c47287580ac38cc039ca92cbcbb397-7773690994834111725742505316101987766894598058473643503939677008623849288002.POLYMARKET");
        let now = Utc::now();
        let start = now - chrono::Duration::hours(6);
        println!("token id:{}",resolve_token_id(&instrument_id));

        let spec = BarSpecification::new(1, 
            BarAggregation::Hour, PriceType::Last);

        let result = client
            .request_bars(&[instrument_id], spec, Some(start), Some(now))
            .await
            .unwrap();

        let bars = result.into_values().flatten().collect::<Vec<_>>();

        println!("=== 5-Minute bars (6h range) ===");
        println!("Received {} bars", bars.len());
        for bar in &bars {
            let secs = bar.ts_event.as_u64() / 1_000_000_000;
            let dt = chrono::DateTime::from_timestamp(secs as i64, 0).unwrap();
            println!(
                "  {}  open={} high={} low={} close={} vol={}",
                dt.format("%Y-%m-%d %H:%M"),
                bar.open,
                bar.high,
                bar.low,
                bar.close,
                bar.volume,
            );
        }
    }
}
