use solana_sdk::{pubkey::Pubkey, signature::Keypair};
use std::str::FromStr;
use anyhow::{Result, anyhow};
use axum::{Json, http::StatusCode};
use crate::types::*;
use crate::ResponseJson;
use solana_sdk::instruction::AccountMeta;
use solana_sdk::system_instruction;
use solana_sdk::system_program;
use spl_associated_token_account::get_associated_token_address;
use base64::Engine;
use solana_sdk::signature::Signer;
use ed25519_dalek::{Verifier, PublicKey, Signature as DalekSignature};

pub fn validate_pubkey(pubkey_str: &str) -> Result<Pubkey> {
    Pubkey::from_str(pubkey_str)
        .map_err(|_| anyhow!("Invalid public key format"))
}

pub fn validate_keypair_from_base58(secret_str: &str) -> Result<Keypair> {
    let secret_bytes = bs58::decode(secret_str)
        .into_vec()
        .map_err(|_| anyhow!("Invalid base58 secret key"))?;
    
    if secret_bytes.len() != 64 {
        return Err(anyhow!("Secret key must be 64 bytes"));
    }
    
    Keypair::from_bytes(&secret_bytes)
        .map_err(|_| anyhow!("Invalid keypair bytes"))
}

pub fn validate_amount(amount: u64) -> Result<()> {
    if amount == 0 {
        return Err(anyhow!("Amount must be greater than 0"));
    }
    Ok(())
}

pub fn validate_lamports(lamports: u64) -> Result<()> {
    if lamports == 0 {
        return Err(anyhow!("Lamports must be greater than 0"));
    }
    Ok(())
}

pub async fn generate_keypair() -> Result<ResponseJson<ApiResponse<KeypairResponse>>, StatusCode> {
    let keypair = Keypair::new();
    let pubkey = bs58::encode(keypair.pubkey().to_bytes()).into_string();
    let secret = bs58::encode(keypair.to_bytes()).into_string();

    Ok(ResponseJson(ApiResponse::success(KeypairResponse {
        pubkey,
        secret,
    })))
}

pub async fn create_token(
    Json(payload): Json<CreateTokenRequest>,
) -> Result<ResponseJson<ApiResponse<InstructionResponse>>, StatusCode> {
    // Validate inputs
    let mint_authority = match validate_pubkey(&payload.mint_authority) {
        Ok(key) => key,
        Err(e) => {
            return Ok(ResponseJson(ApiResponse::<InstructionResponse>::error(e.to_string())));
        }
    };

    let mint = match validate_pubkey(&payload.mint) {
        Ok(key) => key,
        Err(e) => {
            return Ok(ResponseJson(ApiResponse::<InstructionResponse>::error(e.to_string())));
        }
    };

    // Create initialize mint instruction
    let instruction = spl_token::instruction::initialize_mint(
        &spl_token::id(),
        &mint,
        &mint_authority,
        None,
        payload.decimals,
    )
    .map_err(|_| StatusCode::BAD_REQUEST)?;

    let accounts = instruction
        .accounts
        .iter()
        .map(|acc| AccountInfo { pubkey: acc.pubkey.to_string(), is_signer: acc.is_signer, is_writable: acc.is_writable })
        .collect();

    let instruction_data = general_purpose::STANDARD.encode(&instruction.data);

    Ok(ResponseJson(ApiResponse::success(InstructionResponse {
        program_id: instruction.program_id.to_string(),
        accounts,
        instruction_data,
    })))
}

pub async fn mint_token(
    Json(payload): Json<MintTokenRequest>,
) -> Result<ResponseJson<ApiResponse<InstructionResponse>>, StatusCode> {
    // Validate inputs
    let mint = match validate_pubkey(&payload.mint) {
        Ok(key) => key,
        Err(e) => {
            return Ok(ResponseJson(ApiResponse::<InstructionResponse>::error(e.to_string())));
        }
    };

    let destination = match validate_pubkey(&payload.destination) {
        Ok(key) => key,
        Err(e) => {
            return Ok(ResponseJson(ApiResponse::<InstructionResponse>::error(e.to_string())));
        }
    };

    let authority = match validate_pubkey(&payload.authority) {
        Ok(key) => key,
        Err(e) => {
            return Ok(ResponseJson(ApiResponse::<InstructionResponse>::error(e.to_string())));
        }
    };

    if let Err(e) = validate_amount(payload.amount) {
        return Ok(ResponseJson(ApiResponse::<InstructionResponse>::error(e.to_string())));
    }

    // Create mint to instruction
    let instruction = spl_token::instruction::mint_to(
        &spl_token::id(),
        &mint,
        &destination,
        &authority,
        &[],
        payload.amount,
    )
    .map_err(|_| StatusCode::BAD_REQUEST)?;

    let accounts = instruction
        .accounts
        .iter()
        .map(|acc| AccountInfo { pubkey: acc.pubkey.to_string(), is_signer: acc.is_signer, is_writable: acc.is_writable })
        .collect();

    let instruction_data = general_purpose::STANDARD.encode(&instruction.data);

    Ok(ResponseJson(ApiResponse::success(InstructionResponse {
        program_id: instruction.program_id.to_string(),
        accounts,
        instruction_data,
    })))
}

pub async fn sign_message(
    Json(payload): Json<SignMessageRequest>,
) -> Result<ResponseJson<ApiResponse<SignMessageResponse>>, StatusCode> {
    if payload.message.is_empty() || payload.secret.is_empty() {
        return Ok(ResponseJson(ApiResponse::<SignMessageResponse>::error(
            "Missing required fields".to_string(),
        )));
    }

    let keypair = match validate_keypair_from_base58(&payload.secret) {
        Ok(kp) => kp,
        Err(e) => {
            return Ok(ResponseJson(ApiResponse::<SignMessageResponse>::error(e.to_string())));
        }
    };

    let message_bytes = payload.message.as_bytes();
    let signature = keypair.sign_message(message_bytes);
    let signature_base64 = general_purpose::STANDARD.encode(signature.to_bytes());
    let public_key = bs58::encode(keypair.pubkey().to_bytes()).into_string();

    Ok(ResponseJson(ApiResponse::success(SignMessageResponse {
        signature: signature_base64,
        public_key,
        message: payload.message,
    })))
}

pub async fn verify_message(
    Json(payload): Json<VerifyMessageRequest>,
) -> Result<ResponseJson<ApiResponse<VerifyMessageResponse>>, StatusCode> {
    let pubkey = match validate_pubkey(&payload.pubkey) {
        Ok(key) => key,
        Err(e) => {
            return Ok(ResponseJson(ApiResponse::<VerifyMessageResponse>::error(e.to_string())));
        }
    };

    let signature_bytes = match general_purpose::STANDARD.decode(&payload.signature) {
        Ok(bytes) => bytes,
        Err(_) => {
            return Ok(ResponseJson(ApiResponse::<VerifyMessageResponse>::error(
                "Invalid signature format".to_string(),
            )));
        }
    };

    let signature = match DalekSignature::from_bytes(&signature_bytes) {
        Ok(sig) => sig,
        Err(_) => {
            return Ok(ResponseJson(ApiResponse::<VerifyMessageResponse>::error(
                "Invalid signature".to_string(),
            )));
        }
    };

    let public_key_bytes = pubkey.to_bytes();
    let verifying_key = match PublicKey::from_bytes(&public_key_bytes) {
        Ok(key) => key,
        Err(_) => {
            return Ok(ResponseJson(ApiResponse::<VerifyMessageResponse>::error(
                "Invalid public key".to_string(),
            )));
        }
    };

    let message_bytes = payload.message.as_bytes();
    let valid = verifying_key.verify(message_bytes, &signature).is_ok();

    Ok(ResponseJson(ApiResponse::success(VerifyMessageResponse {
        valid,
        message: payload.message,
        pubkey: payload.pubkey,
    })))
}

pub async fn send_sol(
    Json(payload): Json<SendSolRequest>,
) -> Result<ResponseJson<ApiResponse<SolTransferResponse>>, StatusCode> {
    // Validate inputs
    let from = match validate_pubkey(&payload.from) {
        Ok(key) => key,
        Err(e) => {
            return Ok(ResponseJson(ApiResponse::<SolTransferResponse>::error(e.to_string())));
        }
    };

    let to = match validate_pubkey(&payload.to) {
        Ok(key) => key,
        Err(e) => {
            return Ok(ResponseJson(ApiResponse::<SolTransferResponse>::error(e.to_string())));
        }
    };

    if let Err(e) = validate_lamports(payload.lamports) {
        return Ok(ResponseJson(ApiResponse::<SolTransferResponse>::error(e.to_string())));
    }

    // Create transfer instruction
    let instruction = system_instruction::transfer(&from, &to, payload.lamports);

    let accounts = vec![from.to_string(), to.to_string()];
    let instruction_data = general_purpose::STANDARD.encode(&instruction.data);

    Ok(ResponseJson(ApiResponse::success(SolTransferResponse {
        program_id: system_program::id().to_string(),
        accounts,
        instruction_data,
    })))
}

pub async fn send_token(
    Json(payload): Json<SendTokenRequest>,
) -> Result<ResponseJson<ApiResponse<TokenTransferResponse>>, StatusCode> {
    // Validate inputs
    let destination = match validate_pubkey(&payload.destination) {
        Ok(key) => key,
        Err(e) => {
            return Ok(ResponseJson(ApiResponse::<TokenTransferResponse>::error(e.to_string())));
        }
    };

    let mint = match validate_pubkey(&payload.mint) {
        Ok(key) => key,
        Err(e) => {
            return Ok(ResponseJson(ApiResponse::<TokenTransferResponse>::error(e.to_string())));
        }
    };

    let owner = match validate_pubkey(&payload.owner) {
        Ok(key) => key,
        Err(e) => {
            return Ok(ResponseJson(ApiResponse::<TokenTransferResponse>::error(e.to_string())));
        }
    };

    if let Err(e) = validate_amount(payload.amount) {
        return Ok(ResponseJson(ApiResponse::<TokenTransferResponse>::error(e.to_string())));
    }

    // Get associated token accounts
    let source_ata = get_associated_token_address(&owner, &mint);
    let destination_ata = get_associated_token_address(&destination, &mint);

    // Create transfer instruction
    let instruction = spl_token::instruction::transfer(
        &spl_token::id(),
        &source_ata,
        &destination_ata,
        &owner,
        &[],
        payload.amount,
    )
    .map_err(|_| StatusCode::BAD_REQUEST)?;

    let accounts = instruction
        .accounts
        .iter()
        .map(|acc| TokenTransferAccount { pubkey: acc.pubkey.to_string(), is_signer: acc.is_signer })
        .collect();

    let instruction_data = general_purpose::STANDARD.encode(&instruction.data);

    Ok(ResponseJson(ApiResponse::success(TokenTransferResponse {
        program_id: spl_token::id().to_string(),
        accounts,
        instruction_data,
    })))
}