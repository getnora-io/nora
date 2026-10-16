# Swagger UI 5.17.14

The page NORA serves at `/api-docs`, and the files it loads. They are the files of the same name
in the `dist/` folder of Swagger UI 5.17.14 (Apache-2.0: `LICENSE`, `NOTICE`), byte for byte,
except `swagger-initializer.js`: its configuration block names NORA's spec,
`/api-docs/openapi.json`.

The same bytes are in the npm package `swagger-ui-dist@5.17.14` (integrity
`sha512-CVbSfaLpstV65OnSjbXfVd6Sta3q3F7Cj/yYuvHMp1P90LztOLs6PfUnKEVAeiIVQt9u2SaPwv0LiH/OyMjHRw==`)
and in the release zip of `utoipa-swagger-ui-vendored` 0.1.2, which NORA served until these files
replaced it. The source maps and the other bundles of `dist/` are not loaded by the page and are
not here.

`openapi.rs` embeds each file in the binary (`SWAGGER_UI`) and pins its sha256 in a test, so a
file changes only together with its pin.

## Updating

1. Fetch `swagger-ui-dist@<version>` from the npm registry and check the tarball against its
   `integrity`.
2. Copy the files listed in `SWAGGER_UI` from `package/`, and `LICENSE` and `NOTICE`.
3. Keep this `swagger-initializer.js` unless the release changed the file; if it did, take the
   new one and set its configuration block to the one here.
4. Update the pins in `openapi.rs` and the version in this file.
