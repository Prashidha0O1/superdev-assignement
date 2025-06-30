use solana_sdk::{pubkey::Pubkey, signature::Keypair};
use std::str::FromStr;
use anyhow::{Result, anyhow};

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