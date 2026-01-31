// Copyright (c) 2026 Volkov Pavel | DevITWay
// SPDX-License-Identifier: MIT

use serde::{Deserialize, Serialize};
use std::fs;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    pub server: ServerConfig,
    pub storage: StorageConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerConfig {
    pub host: String,
    pub port: u16,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StorageConfig {
    pub data_dir: String,
    pub max_body_size: usize,
}

impl Config {
    pub fn load() -> Self {
        fs::read_to_string("config.toml")
            .ok()
            .and_then(|content| toml::from_str(&content).ok())
            .unwrap_or_default()
    }
}

impl Default for Config {
    fn default() -> Self {
        Self {
            server: ServerConfig {
                host: String::from("127.0.0.1"),
                port: 3000,
            },
            storage: StorageConfig {
                data_dir: String::from("data"),
                max_body_size: 1024 * 1024 * 1024, // 1GB
            },
        }
    }
}
