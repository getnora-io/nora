mod cargo_registry;
mod docker;
mod maven;
mod npm;
mod pypi;

pub use cargo_registry::routes as cargo_routes;
pub use docker::routes as docker_routes;
pub use maven::routes as maven_routes;
pub use npm::routes as npm_routes;
pub use pypi::routes as pypi_routes;
