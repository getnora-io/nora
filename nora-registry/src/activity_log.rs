// Copyright (c) 2026 The NORA Authors
// SPDX-License-Identifier: MIT

use chrono::{DateTime, Utc};
use parking_lot::RwLock;
use serde::Serialize;
use std::collections::VecDeque;
use utoipa::ToSchema;

/// Type of action that was performed
#[derive(Debug, Clone, Serialize, PartialEq, ToSchema)]
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
#[derive(Debug, Clone, Serialize, ToSchema)]
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_action_type_display() {
        assert_eq!(ActionType::Pull.to_string(), "PULL");
        assert_eq!(ActionType::Push.to_string(), "PUSH");
        assert_eq!(ActionType::CacheHit.to_string(), "CACHE");
        assert_eq!(ActionType::ProxyFetch.to_string(), "PROXY");
    }

    #[test]
    fn test_action_type_equality() {
        assert_eq!(ActionType::Pull, ActionType::Pull);
        assert_ne!(ActionType::Pull, ActionType::Push);
    }

    #[test]
    fn test_activity_entry_new() {
        let entry = ActivityEntry::new(
            ActionType::Pull,
            "nginx:latest".to_string(),
            "docker",
            "LOCAL",
        );
        assert_eq!(entry.action, ActionType::Pull);
        assert_eq!(entry.artifact, "nginx:latest");
        assert_eq!(entry.registry, "docker");
        assert_eq!(entry.source, "LOCAL");
    }

    #[test]
    fn test_activity_log_push_and_len() {
        let log = ActivityLog::new(10);
        assert!(log.is_empty());
        assert_eq!(log.len(), 0);

        log.push(ActivityEntry::new(
            ActionType::Push,
            "test:v1".to_string(),
            "docker",
            "LOCAL",
        ));
        assert!(!log.is_empty());
        assert_eq!(log.len(), 1);
    }

    #[test]
    fn test_activity_log_recent() {
        let log = ActivityLog::new(10);
        for i in 0..5 {
            log.push(ActivityEntry::new(
                ActionType::Pull,
                format!("image:{}", i),
                "docker",
                "LOCAL",
            ));
        }

        let recent = log.recent(3);
        assert_eq!(recent.len(), 3);
        // newest first
        assert_eq!(recent[0].artifact, "image:4");
        assert_eq!(recent[1].artifact, "image:3");
        assert_eq!(recent[2].artifact, "image:2");
    }

    #[test]
    fn test_activity_log_all() {
        let log = ActivityLog::new(10);
        for i in 0..3 {
            log.push(ActivityEntry::new(
                ActionType::Pull,
                format!("pkg:{}", i),
                "npm",
                "PROXY",
            ));
        }

        let all = log.all();
        assert_eq!(all.len(), 3);
        assert_eq!(all[0].artifact, "pkg:2"); // newest first
    }

    #[test]
    fn test_activity_log_bounded_size() {
        let log = ActivityLog::new(3);
        for i in 0..5 {
            log.push(ActivityEntry::new(
                ActionType::Pull,
                format!("item:{}", i),
                "cargo",
                "CACHE",
            ));
        }

        assert_eq!(log.len(), 3);
        let all = log.all();
        // oldest entries should be dropped
        assert_eq!(all[0].artifact, "item:4");
        assert_eq!(all[1].artifact, "item:3");
        assert_eq!(all[2].artifact, "item:2");
    }

    #[test]
    fn test_activity_log_recent_more_than_available() {
        let log = ActivityLog::new(10);
        log.push(ActivityEntry::new(
            ActionType::Push,
            "one".to_string(),
            "maven",
            "LOCAL",
        ));

        let recent = log.recent(100);
        assert_eq!(recent.len(), 1);
    }

    #[test]
    fn test_activity_log_default() {
        let log = ActivityLog::default();
        assert!(log.is_empty());
        // default capacity is 50
        for i in 0..60 {
            log.push(ActivityEntry::new(
                ActionType::Pull,
                format!("x:{}", i),
                "docker",
                "LOCAL",
            ));
        }
        assert_eq!(log.len(), 50);
    }
}
