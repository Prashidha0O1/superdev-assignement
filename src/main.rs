use axum::{
    extract::Json,
    http::StatusCode,
    response::Json as ResponseJson,
    routing::post,
    Router,
};
use serde::{Deserialize, Serialize};
use solana_sdk::{ instruction::{AccountMeta, Instruction}, message::Message, pubkey::Pubkey, signature::{Keypair, Signature, Signer}, system_instruction, system_program,};
use spl_token::{ instruction::{initialize_mint, mint_to, transfer}, state::Mint, };
use spl_associated_token_account::{ get_associated_token_address, instruction::create_associated_token_account, };
use std::{env, str::FromStr};
use tower_http::cors::CorsLayer;
use tracing::{info, error};

mod handlers;
mod types;
mod utils;

use handlers::*;
use types::*;

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt::init();

    let app = Router::new()
        .route("/keypair", post(generate_keypair))
        .route("/token/create", post(create_token))
        .route("/token/mint", post(mint_token))
        .route("/message/sign", post(sign_message))
        .route("/message/verify", post(verify_message))
        .route("/send/sol", post(send_sol))
        .route("/send/token", post(send_token))
        .layer(CorsLayer::permissive());

    let port = env::var("PORT").unwrap_or_else(|_| "3000".to_string());
    let addr = format!("0.0.0.0:{}", port);
    let socket_addr = addr.parse().unwrap();
    info!("Server starting on {}", addr);
    axum::Server::bind(&socket_addr)
        .serve(app.into_make_service())
        .await
        .unwrap();
}