// Copyright (c) 2026 The NORA Authors
// SPDX-License-Identifier: MIT

//! Per-registry configuration modules.

mod ansible;
mod cargo;
mod conan;
mod docker;
mod gems;
mod go;
mod maven;
mod npm;
mod nuget;
mod pub_dart;
mod pypi;
mod raw;
mod terraform;

pub use self::ansible::AnsibleConfig;
pub use self::cargo::CargoConfig;
pub use self::conan::ConanConfig;
// Re-export all Docker types including extract_docker_namespace (public API surface)
#[allow(unused_imports)]
pub use self::docker::{extract_docker_namespace, DefaultAction, DockerConfig, DockerUpstream};
pub use self::gems::GemsConfig;
pub use self::go::GoConfig;
#[allow(unused_imports)]
pub use self::maven::{MavenConfig, MavenProxy, MavenProxyEntry};
pub use self::npm::NpmConfig;
pub use self::nuget::NugetConfig;
pub use self::pub_dart::PubDartConfig;
pub use self::pypi::PypiConfig;
pub use self::raw::RawConfig;
pub use self::terraform::TerraformConfig;
