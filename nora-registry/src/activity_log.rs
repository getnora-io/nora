// Copyright (c) 2026 Volkov Pavel | DevITWay
// SPDX-License-Identifier: MIT

use chrono::{DateTime, Utc};
use parking_lot::RwLock;
use serde::Serialize;
use std::collections::VecDeque;

/// Type of action that was performed
#[derive(Debug, Clone, Serialize, PartialEq)]
pub enum ActionType {
    Pull,
    Push,
    CacheHit,
    ProxyFetch,
}

impl std::fmt::Display for ActionType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ActionType::Pull => write!(f, "PULL"),
            ActionType::Push => write!(f, "PUSH"),
            ActionType::CacheHit => write!(f, "CACHE"),
            ActionType::ProxyFetch => write!(f, "PROXY"),
        }
    }
}

/// A single activity log entry
#[derive(Debug, Clone, Serialize)]
pub struct ActivityEntry {
    pub timestamp: DateTime<Utc>,
    pub action: ActionType,
    pub artifact: String,
    pub registry: String,
    pub source: String, // "LOCAL", "PROXY", "CACHE"
}

impl ActivityEntry {
    pub fn new(action: ActionType, artifact: String, registry: &str, source: &str) -> Self {
        Self {
            timestamp: Utc::now(),
            action,
            artifact,
            registry: registry.to_string(),
            source: source.to_string(),
        }
    }
}

/// Thread-safe activity log with bounded size
pub struct ActivityLog {
    entries: RwLock<VecDeque<ActivityEntry>>,
    max_entries: usize,
}

impl ActivityLog {
    pub fn new(max: usize) -> Self {
        Self {
            entries: RwLock::new(VecDeque::with_capacity(max)),
            max_entries: max,
        }
    }

    /// Add a new entry to the log, removing oldest if at capacity
    pub fn push(&self, entry: ActivityEntry) {
        let mut entries = self.entries.write();
        if entries.len() >= self.max_entries {
            entries.pop_front();
        }
        entries.push_back(entry);
    }

    /// Get the most recent N entries (newest first)
    pub fn recent(&self, count: usize) -> Vec<ActivityEntry> {
        let entries = self.entries.read();
        entries.iter().rev().take(count).cloned().collect()
    }

    /// Get all entries (newest first)
    pub fn all(&self) -> Vec<ActivityEntry> {
        let entries = self.entries.read();
        entries.iter().rev().cloned().collect()
    }

    /// Get the total number of entries
    pub fn len(&self) -> usize {
        self.entries.read().len()
    }

    /// Check if the log is empty
    pub fn is_empty(&self) -> bool {
        self.entries.read().is_empty()
    }
}

impl Default for ActivityLog {
    fn default() -> Self {
        Self::new(50)
    }
}
