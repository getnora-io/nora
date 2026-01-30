mod cargo_registry;
pub mod docker;
pub mod docker_auth;
mod maven;
mod npm;
mod pypi;
mod raw;

pub use cargo_registry::routes as cargo_routes;
pub use docker::routes as docker_routes;
pub use docker_auth::DockerAuth;
pub use maven::routes as maven_routes;
pub use npm::routes as npm_routes;
pub use pypi::routes as pypi_routes;
pub use raw::routes as raw_routes;
