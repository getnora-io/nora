// Copyright (c) 2026 The NORA Authors
// SPDX-License-Identifier: MIT

//! Shared Nexus-compatible `/repository/{repository}/...` dispatcher.
//!
//! Maven and npm intentionally use the same public repository namespace.
//! Mounting one wildcard route per protocol makes Axum's routers conflict and
//! leaves the format ambiguous. Configuration validation guarantees global
//! name uniqueness; this dispatcher resolves the concrete name and invokes the
//! matching protocol handler without guessing from naming conventions.

use super::method_not_allowed;
use crate::auth::{enforce_namespace_scope, AuthenticatedUser, NamespaceAuthority};
use crate::AppState;
use axum::{
    body::{Body, Bytes},
    extract::{OriginalUri, Path, State},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    routing::get,
    Extension, Router,
};

pub fn routes() -> Router<AppState> {
    Router::new().route(
        "/repository/{repository}/{*path}",
        get(download)
            .put(upload)
            .post(post)
            .fallback(|| async { method_not_allowed("GET, PUT, POST") }),
    )
}

async fn download(
    State(state): State<AppState>,
    Path((repository, path)): Path<(String, String)>,
    OriginalUri(uri): OriginalUri,
    headers: HeaderMap,
    Extension(user): Extension<AuthenticatedUser>,
) -> Response {
    if state.config.maven.enabled && state.config.maven.repository(&repository).is_some() {
        return super::maven::download_named(State(state), headers, Path((repository, path))).await;
    }
    if state.config.npm.enabled && state.config.npm.repository(&repository).is_some() {
        return super::npm::named_get_request(state, repository, path, uri, headers, user).await;
    }
    StatusCode::NOT_FOUND.into_response()
}

async fn upload(
    State(state): State<AppState>,
    Path((repository, path)): Path<(String, String)>,
    headers: HeaderMap,
    Extension(authority): Extension<NamespaceAuthority>,
    body: Bytes,
) -> Response {
    if state.config.maven.enabled && state.config.maven.repository(&repository).is_some() {
        let authorize =
            move |namespace: &str| enforce_namespace_scope(&authority, namespace).is_ok();
        return super::maven::upload_named(State(state), Path((repository, path)), body, authorize)
            .await;
    }
    if state.config.npm.enabled && state.config.npm.repository(&repository).is_some() {
        let authorize = move |package: &str| enforce_namespace_scope(&authority, package).is_ok();
        return super::npm::named_put_request(state, repository, path, headers, body, authorize)
            .await;
    }
    StatusCode::NOT_FOUND.into_response()
}

async fn post(
    State(state): State<AppState>,
    Path((repository, path)): Path<(String, String)>,
    headers: HeaderMap,
    body: Body,
) -> Response {
    if state.config.maven.enabled && state.config.maven.repository(&repository).is_some() {
        return method_not_allowed("GET, PUT");
    }
    if state.config.npm.enabled && state.config.npm.repository(&repository).is_some() {
        return super::npm::named_post_request(state, repository, path, headers, body).await;
    }
    StatusCode::NOT_FOUND.into_response()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{
        MavenRepository, MavenVersionPolicy, MavenWritePolicy, NpmRepository, NpmWritePolicy,
    };
    use crate::test_helpers::{
        body_bytes, create_test_context_with_config, npm_publish_payload, send, TestContext,
    };
    use axum::http::Method;

    fn combined_named_config(config: &mut crate::config::Config) {
        config.maven.repositories = vec![MavenRepository::Hosted {
            name: "maven-releases".to_string(),
            version_policy: MavenVersionPolicy::Release,
            write_policy: MavenWritePolicy::AllowOnce,
        }];
        config.maven.default_repository = Some("maven-releases".to_string());
        config.npm.repositories = vec![NpmRepository::Hosted {
            name: "npm-private".to_string(),
            write_policy: NpmWritePolicy::AllowOnce,
        }];
        config.npm.default_repository = Some("npm-private".to_string());
    }

    async fn seed_npm_package(context: &TestContext, package: &str) {
        assert_eq!(
            send(
                &context.app,
                Method::PUT,
                &format!("/repository/npm-private/{package}"),
                npm_publish_payload(package, "1.0.0", "latest"),
            )
            .await
            .status(),
            StatusCode::CREATED
        );
    }

    #[tokio::test]
    async fn shared_dispatcher_reaches_maven_and_npm_without_route_conflict() {
        // Constructing the combined test router is itself a regression for the
        // Axum wildcard conflict that separate protocol routers caused.
        let context = create_test_context_with_config(combined_named_config);

        let maven_path = "/repository/maven-releases/com/example/app/1.0/app-1.0.jar";
        let uploaded = send(
            &context.app,
            Method::PUT,
            maven_path,
            b"maven-bytes".as_slice(),
        )
        .await;
        assert_eq!(uploaded.status(), StatusCode::CREATED);
        let downloaded = send(&context.app, Method::GET, maven_path, "").await;
        assert_eq!(downloaded.status(), StatusCode::OK);
        assert_eq!(body_bytes(downloaded).await.as_ref(), b"maven-bytes");

        seed_npm_package(&context, "pkg").await;
        let npm_path = "/repository/npm-private/pkg";
        let deprecated = send(
            &context.app,
            Method::PUT,
            npm_path,
            br#"{"name":"pkg","versions":{"1.0.0":{"deprecated":"old"}}}"#.as_slice(),
        )
        .await;
        assert_eq!(deprecated.status(), StatusCode::CREATED);
        assert_eq!(
            context
                .state
                .storage
                .get("npm/repositories/npm-private/pkg/deprecations/1.0.0")
                .await
                .unwrap()
                .as_ref(),
            b"old"
        );
        let npm = send(&context.app, Method::GET, npm_path, "").await;
        assert_eq!(npm.status(), StatusCode::OK);
        let npm_json: serde_json::Value = serde_json::from_slice(&body_bytes(npm).await).unwrap();
        assert_eq!(npm_json["versions"]["1.0.0"]["name"], "pkg");

        assert_eq!(
            send(
                &context.app,
                Method::PUT,
                "/repository/npm-private/-/package/pkg/dist-tags/next",
                serde_json::to_vec("1.0.0").unwrap(),
            )
            .await
            .status(),
            StatusCode::CREATED
        );
        let deleted = send(
            &context.app,
            Method::DELETE,
            "/repository/npm-private/-/package/pkg/dist-tags/next",
            "",
        )
        .await;
        assert_eq!(deleted.status(), StatusCode::NO_CONTENT);
        assert!(context
            .state
            .storage
            .get("npm/repositories/npm-private/pkg/dist-tags/next")
            .await
            .is_err());

        assert_eq!(
            send(&context.app, Method::DELETE, maven_path, "")
                .await
                .status(),
            StatusCode::METHOD_NOT_ALLOWED
        );

        let unknown = send(
            &context.app,
            Method::GET,
            "/repository/no-such-repository/pkg",
            "",
        )
        .await;
        assert_eq!(unknown.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn shared_dispatcher_enforces_protocol_canonical_namespace_once() {
        use crate::config::ScopeEnforcement;

        let context = create_test_context_with_config(combined_named_config);
        let maven_scope = NamespaceAuthority::from_oidc_scope(
            "ci",
            &["com/myorg/**".to_string()],
            ScopeEnforcement::Enforce,
        );
        let denied_maven = upload(
            State(context.state.clone()),
            Path((
                "maven-releases".to_string(),
                "com/other/app/1.0/app-1.0.jar".to_string(),
            )),
            HeaderMap::new(),
            Extension(maven_scope.clone()),
            Bytes::from_static(b"denied"),
        )
        .await;
        assert_eq!(denied_maven.status(), StatusCode::FORBIDDEN);
        let allowed_maven = upload(
            State(context.state.clone()),
            Path((
                "maven-releases".to_string(),
                "com/myorg/app/1.0/app-1.0.jar".to_string(),
            )),
            HeaderMap::new(),
            Extension(maven_scope),
            Bytes::from_static(b"allowed"),
        )
        .await;
        assert_eq!(allowed_maven.status(), StatusCode::CREATED);

        let npm_scope = NamespaceAuthority::from_oidc_scope(
            "ci",
            &["@myorg/**".to_string()],
            ScopeEnforcement::Enforce,
        );
        let denied_npm = upload(
            State(context.state.clone()),
            Path(("npm-private".to_string(), "other-package".to_string())),
            HeaderMap::new(),
            Extension(npm_scope.clone()),
            Bytes::from(npm_publish_payload("other-package", "1.0.0", "latest")),
        )
        .await;
        assert_eq!(denied_npm.status(), StatusCode::FORBIDDEN);
        let allowed_npm = upload(
            State(context.state.clone()),
            Path(("npm-private".to_string(), "%40myorg%2Fpackage".to_string())),
            HeaderMap::new(),
            Extension(npm_scope),
            Bytes::from(npm_publish_payload("@myorg/package", "1.0.0", "latest")),
        )
        .await;
        assert_eq!(allowed_npm.status(), StatusCode::CREATED);
    }

    #[tokio::test]
    async fn shared_dispatcher_blocks_configured_npm_when_protocol_is_disabled() {
        let context = create_test_context_with_config(|config| {
            combined_named_config(config);
            config.npm.enabled = false;
        });

        let maven_path = "/repository/maven-releases/com/example/app/1.0/app-1.0.jar";
        assert_eq!(
            send(
                &context.app,
                Method::PUT,
                maven_path,
                b"maven-bytes".as_slice(),
            )
            .await
            .status(),
            StatusCode::CREATED
        );
        assert_eq!(
            send(&context.app, Method::GET, "/repository/npm-private/pkg", "",)
                .await
                .status(),
            StatusCode::NOT_FOUND
        );
    }

    #[tokio::test]
    async fn shared_dispatcher_blocks_configured_maven_when_protocol_is_disabled() {
        let context = create_test_context_with_config(|config| {
            combined_named_config(config);
            config.maven.enabled = false;
        });
        seed_npm_package(&context, "pkg").await;

        assert_eq!(
            send(&context.app, Method::GET, "/repository/npm-private/pkg", "",)
                .await
                .status(),
            StatusCode::OK
        );
        assert_eq!(
            send(
                &context.app,
                Method::GET,
                "/repository/maven-releases/com/example/app/1.0/app-1.0.jar",
                "",
            )
            .await
            .status(),
            StatusCode::NOT_FOUND
        );
    }
}
