use serde::Deserialize;
use std::{collections::HashMap, fs};

#[derive(Debug, Clone, Deserialize)]
pub struct ServerConfig {
    pub host: String,
    pub port: u16,
    pub endpoint: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct OAuth2Config {
    pub redirect_uri: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct CASConfig {
    pub login_url: String,
    pub validate_url: String,
    pub service_param: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct JWTConfig {
    pub secret: String,
    pub expiration: i64,
}

#[derive(Debug, Clone, Deserialize)]
pub struct Config {
    pub server: ServerConfig,
    pub oauth2: OAuth2Config,
    pub cas: CASConfig,
    pub jwt: JWTConfig,
    #[serde(default)]
    pub field_mapping: HashMap<String, String>,
}

impl Config {
    pub fn load() -> Result<Self, Box<dyn std::error::Error>> {
        let config_str = fs::read_to_string("config/config.toml")?;
        let config: Config = toml::from_str(&config_str)?;
        Ok(config)
    }
}
