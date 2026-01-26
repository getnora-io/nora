use super::api::{DockerDetail, MavenDetail, PackageDetail, RegistryStats, RepoInfo};
use super::components::*;

/// Renders the main dashboard page
pub fn render_dashboard(stats: &RegistryStats) -> String {
    let content = format!(
        r##"
        <div class="mb-8">
            <h1 class="text-2xl font-bold text-slate-800 mb-2">Dashboard</h1>
            <p class="text-slate-500">Overview of all registries</p>
        </div>

        <div class="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 xl:grid-cols-5 gap-6 mb-8">
            {}
            {}
            {}
            {}
            {}
        </div>

        <div class="bg-white rounded-lg shadow-sm border border-slate-200 p-6">
            <h2 class="text-lg font-semibold text-slate-800 mb-4">Quick Links</h2>
            <div class="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
                <a href="/ui/docker" class="flex items-center p-3 rounded-lg border border-slate-200 hover:border-blue-300 hover:bg-blue-50 transition-colors">
                    <svg class="w-8 h-8 mr-3 text-slate-600" fill="currentColor" viewBox="0 0 24 24">{}</svg>
                    <div>
                        <div class="font-medium text-slate-700">Docker Registry</div>
                        <div class="text-sm text-slate-500">API: /v2/</div>
                    </div>
                </a>
                <a href="/ui/maven" class="flex items-center p-3 rounded-lg border border-slate-200 hover:border-blue-300 hover:bg-blue-50 transition-colors">
                    <svg class="w-8 h-8 mr-3 text-slate-600" fill="currentColor" viewBox="0 0 24 24">{}</svg>
                    <div>
                        <div class="font-medium text-slate-700">Maven Repository</div>
                        <div class="text-sm text-slate-500">API: /maven2/</div>
                    </div>
                </a>
                <a href="/ui/npm" class="flex items-center p-3 rounded-lg border border-slate-200 hover:border-blue-300 hover:bg-blue-50 transition-colors">
                    <svg class="w-8 h-8 mr-3 text-slate-600" fill="currentColor" viewBox="0 0 24 24">{}</svg>
                    <div>
                        <div class="font-medium text-slate-700">npm Registry</div>
                        <div class="text-sm text-slate-500">API: /npm/</div>
                    </div>
                </a>
                <a href="/ui/cargo" class="flex items-center p-3 rounded-lg border border-slate-200 hover:border-blue-300 hover:bg-blue-50 transition-colors">
                    <svg class="w-8 h-8 mr-3 text-slate-600" fill="currentColor" viewBox="0 0 24 24">{}</svg>
                    <div>
                        <div class="font-medium text-slate-700">Cargo Registry</div>
                        <div class="text-sm text-slate-500">API: /cargo/</div>
                    </div>
                </a>
                <a href="/ui/pypi" class="flex items-center p-3 rounded-lg border border-slate-200 hover:border-blue-300 hover:bg-blue-50 transition-colors">
                    <svg class="w-8 h-8 mr-3 text-slate-600" fill="currentColor" viewBox="0 0 24 24">{}</svg>
                    <div>
                        <div class="font-medium text-slate-700">PyPI Repository</div>
                        <div class="text-sm text-slate-500">API: /simple/</div>
                    </div>
                </a>
            </div>
        </div>
    "##,
        stat_card(
            "Docker",
            icons::DOCKER,
            stats.docker,
            "/ui/docker",
            "images"
        ),
        stat_card("Maven", icons::MAVEN, stats.maven, "/ui/maven", "artifacts"),
        stat_card("npm", icons::NPM, stats.npm, "/ui/npm", "packages"),
        stat_card("Cargo", icons::CARGO, stats.cargo, "/ui/cargo", "crates"),
        stat_card("PyPI", icons::PYPI, stats.pypi, "/ui/pypi", "packages"),
        // Quick Links icons
        icons::DOCKER,
        icons::MAVEN,
        icons::NPM,
        icons::CARGO,
        icons::PYPI,
    );

    layout("Dashboard", &content, Some("dashboard"))
}

/// Renders a registry list page (docker, maven, npm, cargo, pypi)
pub fn render_registry_list(registry_type: &str, title: &str, repos: &[RepoInfo]) -> String {
    let icon = get_registry_icon(registry_type);

    let table_rows = if repos.is_empty() {
        r##"<tr><td colspan="4" class="px-6 py-12 text-center text-slate-500">
            <div class="text-4xl mb-2">📭</div>
            <div>No repositories found</div>
            <div class="text-sm mt-1">Push your first artifact to see it here</div>
        </td></tr>"##
            .to_string()
    } else {
        repos
            .iter()
            .map(|repo| {
                let detail_url =
                    format!("/ui/{}/{}", registry_type, encode_uri_component(&repo.name));
                format!(
                    r##"
                <tr class="hover:bg-slate-50 cursor-pointer" onclick="window.location='{}'">
                    <td class="px-6 py-4">
                        <a href="{}" class="text-blue-600 hover:text-blue-800 font-medium">{}</a>
                    </td>
                    <td class="px-6 py-4 text-slate-600">{}</td>
                    <td class="px-6 py-4 text-slate-600">{}</td>
                    <td class="px-6 py-4 text-slate-500 text-sm">{}</td>
                </tr>
            "##,
                    detail_url,
                    detail_url,
                    html_escape(&repo.name),
                    repo.versions,
                    format_size(repo.size),
                    &repo.updated
                )
            })
            .collect::<Vec<_>>()
            .join("")
    };

    let version_label = match registry_type {
        "docker" => "Tags",
        "maven" => "Versions",
        _ => "Versions",
    };

    let content = format!(
        r##"
        <div class="mb-6 flex items-center justify-between">
            <div class="flex items-center">
                <svg class="w-10 h-10 mr-3 text-slate-600" fill="currentColor" viewBox="0 0 24 24">{}</svg>
                <div>
                    <h1 class="text-2xl font-bold text-slate-800">{}</h1>
                    <p class="text-slate-500">{} repositories</p>
                </div>
            </div>
            <div class="flex items-center gap-4">
                <div class="relative">
                    <input type="text"
                           placeholder="Search repositories..."
                           class="pl-10 pr-4 py-2 border border-slate-300 rounded-lg focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-transparent"
                           hx-get="/api/ui/{}/search"
                           hx-trigger="keyup changed delay:300ms"
                           hx-target="#repo-table-body"
                           name="q">
                    <svg class="absolute left-3 top-2.5 h-5 w-5 text-slate-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                        <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M21 21l-6-6m2-5a7 7 0 11-14 0 7 7 0 0114 0z"/>
                    </svg>
                </div>
            </div>
        </div>

        <div class="bg-white rounded-lg shadow-sm border border-slate-200 overflow-hidden">
            <table class="w-full">
                <thead class="bg-slate-50 border-b border-slate-200">
                    <tr>
                        <th class="px-6 py-3 text-left text-xs font-semibold text-slate-600 uppercase tracking-wider">Name</th>
                        <th class="px-6 py-3 text-left text-xs font-semibold text-slate-600 uppercase tracking-wider">{}</th>
                        <th class="px-6 py-3 text-left text-xs font-semibold text-slate-600 uppercase tracking-wider">Size</th>
                        <th class="px-6 py-3 text-left text-xs font-semibold text-slate-600 uppercase tracking-wider">Updated</th>
                    </tr>
                </thead>
                <tbody id="repo-table-body" class="divide-y divide-slate-200">
                    {}
                </tbody>
            </table>
        </div>
    "##,
        icon,
        title,
        repos.len(),
        registry_type,
        version_label,
        table_rows
    );

    layout(title, &content, Some(registry_type))
}

/// Renders Docker image detail page
pub fn render_docker_detail(name: &str, detail: &DockerDetail) -> String {
    let tags_rows = if detail.tags.is_empty() {
        r##"<tr><td colspan="3" class="px-6 py-8 text-center text-slate-500">No tags found</td></tr>"##.to_string()
    } else {
        detail
            .tags
            .iter()
            .map(|tag| {
                format!(
                    r##"
                <tr class="hover:bg-slate-50">
                    <td class="px-6 py-4">
                        <span class="font-mono text-sm bg-slate-100 px-2 py-1 rounded">{}</span>
                    </td>
                    <td class="px-6 py-4 text-slate-600">{}</td>
                    <td class="px-6 py-4 text-slate-500 text-sm">{}</td>
                </tr>
            "##,
                    html_escape(&tag.name),
                    format_size(tag.size),
                    &tag.created
                )
            })
            .collect::<Vec<_>>()
            .join("")
    };

    let pull_cmd = format!("docker pull 127.0.0.1:4000/{}", name);

    let content = format!(
        r##"
        <div class="mb-6">
            <div class="flex items-center mb-2">
                <a href="/ui/docker" class="text-blue-600 hover:text-blue-800">Docker Registry</a>
                <span class="mx-2 text-slate-400">/</span>
                <span class="text-slate-800 font-medium">{}</span>
            </div>
            <div class="flex items-center">
                <svg class="w-10 h-10 mr-3 text-slate-600" fill="currentColor" viewBox="0 0 24 24">{}</svg>
                <h1 class="text-2xl font-bold text-slate-800">{}</h1>
            </div>
        </div>

        <div class="bg-white rounded-lg shadow-sm border border-slate-200 p-6 mb-6">
            <h2 class="text-lg font-semibold text-slate-800 mb-3">Pull Command</h2>
            <div class="flex items-center bg-slate-900 text-green-400 rounded-lg p-4 font-mono text-sm">
                <code class="flex-1">{}</code>
                <button onclick="navigator.clipboard.writeText('{}')" class="ml-4 text-slate-400 hover:text-white transition-colors" title="Copy to clipboard">
                    <svg class="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                        <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M8 16H6a2 2 0 01-2-2V6a2 2 0 012-2h8a2 2 0 012 2v2m-6 12h8a2 2 0 002-2v-8a2 2 0 00-2-2h-8a2 2 0 00-2 2v8a2 2 0 002 2z"/>
                    </svg>
                </button>
            </div>
        </div>

        <div class="bg-white rounded-lg shadow-sm border border-slate-200 overflow-hidden">
            <div class="px-6 py-4 border-b border-slate-200">
                <h2 class="text-lg font-semibold text-slate-800">Tags ({} total)</h2>
            </div>
            <table class="w-full">
                <thead class="bg-slate-50 border-b border-slate-200">
                    <tr>
                        <th class="px-6 py-3 text-left text-xs font-semibold text-slate-600 uppercase tracking-wider">Tag</th>
                        <th class="px-6 py-3 text-left text-xs font-semibold text-slate-600 uppercase tracking-wider">Size</th>
                        <th class="px-6 py-3 text-left text-xs font-semibold text-slate-600 uppercase tracking-wider">Created</th>
                    </tr>
                </thead>
                <tbody class="divide-y divide-slate-200">
                    {}
                </tbody>
            </table>
        </div>
    "##,
        html_escape(name),
        icons::DOCKER,
        html_escape(name),
        pull_cmd,
        pull_cmd,
        detail.tags.len(),
        tags_rows
    );

    layout(&format!("{} - Docker", name), &content, Some("docker"))
}

/// Renders package detail page (npm, cargo, pypi)
pub fn render_package_detail(registry_type: &str, name: &str, detail: &PackageDetail) -> String {
    let icon = get_registry_icon(registry_type);
    let registry_title = get_registry_title(registry_type);

    let versions_rows = if detail.versions.is_empty() {
        r##"<tr><td colspan="3" class="px-6 py-8 text-center text-slate-500">No versions found</td></tr>"##.to_string()
    } else {
        detail
            .versions
            .iter()
            .map(|v| {
                format!(
                    r##"
                <tr class="hover:bg-slate-50">
                    <td class="px-6 py-4">
                        <span class="font-mono text-sm bg-slate-100 px-2 py-1 rounded">{}</span>
                    </td>
                    <td class="px-6 py-4 text-slate-600">{}</td>
                    <td class="px-6 py-4 text-slate-500 text-sm">{}</td>
                </tr>
            "##,
                    html_escape(&v.version),
                    format_size(v.size),
                    &v.published
                )
            })
            .collect::<Vec<_>>()
            .join("")
    };

    let install_cmd = match registry_type {
        "npm" => format!("npm install {} --registry http://127.0.0.1:4000/npm", name),
        "cargo" => format!("cargo add {}", name),
        "pypi" => format!(
            "pip install {} --index-url http://127.0.0.1:4000/simple",
            name
        ),
        _ => String::new(),
    };

    let content = format!(
        r##"
        <div class="mb-6">
            <div class="flex items-center mb-2">
                <a href="/ui/{}" class="text-blue-600 hover:text-blue-800">{}</a>
                <span class="mx-2 text-slate-400">/</span>
                <span class="text-slate-800 font-medium">{}</span>
            </div>
            <div class="flex items-center">
                <svg class="w-10 h-10 mr-3 text-slate-600" fill="currentColor" viewBox="0 0 24 24">{}</svg>
                <h1 class="text-2xl font-bold text-slate-800">{}</h1>
            </div>
        </div>

        <div class="bg-white rounded-lg shadow-sm border border-slate-200 p-6 mb-6">
            <h2 class="text-lg font-semibold text-slate-800 mb-3">Install Command</h2>
            <div class="flex items-center bg-slate-900 text-green-400 rounded-lg p-4 font-mono text-sm">
                <code class="flex-1">{}</code>
                <button onclick="navigator.clipboard.writeText('{}')" class="ml-4 text-slate-400 hover:text-white transition-colors" title="Copy to clipboard">
                    <svg class="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                        <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M8 16H6a2 2 0 01-2-2V6a2 2 0 012-2h8a2 2 0 012 2v2m-6 12h8a2 2 0 002-2v-8a2 2 0 00-2-2h-8a2 2 0 00-2 2v8a2 2 0 002 2z"/>
                    </svg>
                </button>
            </div>
        </div>

        <div class="bg-white rounded-lg shadow-sm border border-slate-200 overflow-hidden">
            <div class="px-6 py-4 border-b border-slate-200">
                <h2 class="text-lg font-semibold text-slate-800">Versions ({} total)</h2>
            </div>
            <table class="w-full">
                <thead class="bg-slate-50 border-b border-slate-200">
                    <tr>
                        <th class="px-6 py-3 text-left text-xs font-semibold text-slate-600 uppercase tracking-wider">Version</th>
                        <th class="px-6 py-3 text-left text-xs font-semibold text-slate-600 uppercase tracking-wider">Size</th>
                        <th class="px-6 py-3 text-left text-xs font-semibold text-slate-600 uppercase tracking-wider">Published</th>
                    </tr>
                </thead>
                <tbody class="divide-y divide-slate-200">
                    {}
                </tbody>
            </table>
        </div>
    "##,
        registry_type,
        registry_title,
        html_escape(name),
        icon,
        html_escape(name),
        install_cmd,
        install_cmd,
        detail.versions.len(),
        versions_rows
    );

    layout(
        &format!("{} - {}", name, registry_title),
        &content,
        Some(registry_type),
    )
}

/// Renders Maven artifact detail page
pub fn render_maven_detail(path: &str, detail: &MavenDetail) -> String {
    let artifact_rows = if detail.artifacts.is_empty() {
        r##"<tr><td colspan="2" class="px-6 py-8 text-center text-slate-500">No artifacts found</td></tr>"##.to_string()
    } else {
        detail.artifacts.iter().map(|a| {
            let download_url = format!("/maven2/{}/{}", path, a.filename);
            format!(r##"
                <tr class="hover:bg-slate-50">
                    <td class="px-6 py-4">
                        <a href="{}" class="text-blue-600 hover:text-blue-800 font-mono text-sm">{}</a>
                    </td>
                    <td class="px-6 py-4 text-slate-600">{}</td>
                </tr>
            "##, download_url, html_escape(&a.filename), format_size(a.size))
        }).collect::<Vec<_>>().join("")
    };

    // Extract artifact name from path (last component before version)
    let parts: Vec<&str> = path.split('/').collect();
    let artifact_name = if parts.len() >= 2 {
        parts[parts.len() - 2]
    } else {
        path
    };

    let dep_cmd = format!(
        r#"<dependency>
    <groupId>{}</groupId>
    <artifactId>{}</artifactId>
    <version>{}</version>
</dependency>"#,
        parts[..parts.len().saturating_sub(2)].join("."),
        artifact_name,
        parts.last().unwrap_or(&"")
    );

    let content = format!(
        r##"
        <div class="mb-6">
            <div class="flex items-center mb-2">
                <a href="/ui/maven" class="text-blue-600 hover:text-blue-800">Maven Repository</a>
                <span class="mx-2 text-slate-400">/</span>
                <span class="text-slate-800 font-medium">{}</span>
            </div>
            <div class="flex items-center">
                <svg class="w-10 h-10 mr-3 text-slate-600" fill="currentColor" viewBox="0 0 24 24">{}</svg>
                <h1 class="text-2xl font-bold text-slate-800">{}</h1>
            </div>
        </div>

        <div class="bg-white rounded-lg shadow-sm border border-slate-200 p-6 mb-6">
            <h2 class="text-lg font-semibold text-slate-800 mb-3">Maven Dependency</h2>
            <pre class="bg-slate-900 text-green-400 rounded-lg p-4 font-mono text-sm overflow-x-auto">{}</pre>
        </div>

        <div class="bg-white rounded-lg shadow-sm border border-slate-200 overflow-hidden">
            <div class="px-6 py-4 border-b border-slate-200">
                <h2 class="text-lg font-semibold text-slate-800">Artifacts ({} files)</h2>
            </div>
            <table class="w-full">
                <thead class="bg-slate-50 border-b border-slate-200">
                    <tr>
                        <th class="px-6 py-3 text-left text-xs font-semibold text-slate-600 uppercase tracking-wider">Filename</th>
                        <th class="px-6 py-3 text-left text-xs font-semibold text-slate-600 uppercase tracking-wider">Size</th>
                    </tr>
                </thead>
                <tbody class="divide-y divide-slate-200">
                    {}
                </tbody>
            </table>
        </div>
    "##,
        html_escape(path),
        icons::MAVEN,
        html_escape(path),
        html_escape(&dep_cmd),
        detail.artifacts.len(),
        artifact_rows
    );

    layout(&format!("{} - Maven", path), &content, Some("maven"))
}

/// Returns SVG icon path for the registry type
fn get_registry_icon(registry_type: &str) -> &'static str {
    match registry_type {
        "docker" => icons::DOCKER,
        "maven" => icons::MAVEN,
        "npm" => icons::NPM,
        "cargo" => icons::CARGO,
        "pypi" => icons::PYPI,
        _ => {
            r#"<path fill="currentColor" d="M10 4H4c-1.1 0-1.99.9-1.99 2L2 18c0 1.1.9 2 2 2h16c1.1 0 2-.9 2-2V8c0-1.1-.9-2-2-2h-8l-2-2z"/>"#
        }
    }
}

fn get_registry_title(registry_type: &str) -> &'static str {
    match registry_type {
        "docker" => "Docker Registry",
        "maven" => "Maven Repository",
        "npm" => "npm Registry",
        "cargo" => "Cargo Registry",
        "pypi" => "PyPI Repository",
        _ => "Registry",
    }
}

/// Simple URL encoding for path components
pub fn encode_uri_component(s: &str) -> String {
    let mut result = String::new();
    for c in s.chars() {
        match c {
            'a'..='z' | 'A'..='Z' | '0'..='9' | '-' | '_' | '.' | '~' => result.push(c),
            _ => {
                for byte in c.to_string().as_bytes() {
                    result.push_str(&format!("%{:02X}", byte));
                }
            }
        }
    }
    result
}
