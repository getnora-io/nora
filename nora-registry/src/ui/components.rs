/// Application version from Cargo.toml
const VERSION: &str = env!("CARGO_PKG_VERSION");

/// Dark theme layout wrapper for dashboard
pub fn layout_dark(
    title: &str,
    content: &str,
    active_page: Option<&str>,
    extra_scripts: &str,
) -> String {
    format!(
        r##"<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{} - Nora</title>
    <script src="https://cdn.tailwindcss.com"></script>
    <script src="https://unpkg.com/htmx.org@1.9.10"></script>
    <style>
        [x-cloak] {{ display: none !important; }}
        .sidebar-open {{ overflow: hidden; }}
    </style>
</head>
<body class="bg-[#0f172a] min-h-screen">
    <div class="flex h-screen overflow-hidden">
        <!-- Mobile sidebar overlay -->
        <div id="sidebar-overlay" class="fixed inset-0 bg-black/50 z-40 hidden md:hidden" onclick="toggleSidebar()"></div>

        <!-- Sidebar -->
        {}

        <!-- Main content -->
        <div class="flex-1 flex flex-col overflow-hidden min-w-0">
            <!-- Header -->
            {}

            <!-- Content -->
            <main class="flex-1 overflow-y-auto p-4 md:p-6">
                {}
            </main>
        </div>
    </div>

    <script>
        function toggleSidebar() {{
            const sidebar = document.getElementById('sidebar');
            const overlay = document.getElementById('sidebar-overlay');
            const isOpen = !sidebar.classList.contains('-translate-x-full');

            if (isOpen) {{
                sidebar.classList.add('-translate-x-full');
                overlay.classList.add('hidden');
                document.body.classList.remove('sidebar-open');
            }} else {{
                sidebar.classList.remove('-translate-x-full');
                overlay.classList.remove('hidden');
                document.body.classList.add('sidebar-open');
            }}
        }}
    </script>
    {}
</body>
</html>"##,
        html_escape(title),
        sidebar_dark(active_page),
        header_dark(),
        content,
        extra_scripts
    )
}

/// Dark theme sidebar
fn sidebar_dark(active_page: Option<&str>) -> String {
    let active = active_page.unwrap_or("");

    let docker_icon = r#"<path fill="currentColor" d="M13.983 11.078h2.119a.186.186 0 00.186-.185V9.006a.186.186 0 00-.186-.186h-2.119a.185.185 0 00-.185.185v1.888c0 .102.083.185.185.185m-2.954-5.43h2.118a.186.186 0 00.186-.186V3.574a.186.186 0 00-.186-.185h-2.118a.185.185 0 00-.185.185v1.888c0 .102.082.185.185.186m0 2.716h2.118a.187.187 0 00.186-.186V6.29a.186.186 0 00-.186-.185h-2.118a.185.185 0 00-.185.185v1.887c0 .102.082.185.185.186m-2.93 0h2.12a.186.186 0 00.184-.186V6.29a.185.185 0 00-.185-.185H8.1a.185.185 0 00-.185.185v1.887c0 .102.083.185.185.186m-2.964 0h2.119a.186.186 0 00.185-.186V6.29a.185.185 0 00-.185-.185H5.136a.186.186 0 00-.186.185v1.887c0 .102.084.185.186.186m5.893 2.715h2.118a.186.186 0 00.186-.185V9.006a.186.186 0 00-.186-.186h-2.118a.185.185 0 00-.185.185v1.888c0 .102.082.185.185.185m-2.93 0h2.12a.185.185 0 00.184-.185V9.006a.185.185 0 00-.184-.186h-2.12a.185.185 0 00-.184.185v1.888c0 .102.083.185.185.185m-2.964 0h2.119a.185.185 0 00.185-.185V9.006a.185.185 0 00-.185-.186h-2.12a.186.186 0 00-.185.186v1.887c0 .102.084.185.186.185m-2.92 0h2.12a.185.185 0 00.184-.185V9.006a.185.185 0 00-.184-.186h-2.12a.185.185 0 00-.184.185v1.888c0 .102.082.185.185.185M23.763 9.89c-.065-.051-.672-.51-1.954-.51-.338.001-.676.03-1.01.087-.248-1.7-1.653-2.53-1.716-2.566l-.344-.199-.226.327c-.284.438-.49.922-.612 1.43-.23.97-.09 1.882.403 2.661-.595.332-1.55.413-1.744.42H.751a.751.751 0 00-.75.748 11.376 11.376 0 00.692 4.062c.545 1.428 1.355 2.48 2.41 3.124 1.18.723 3.1 1.137 5.275 1.137.983.003 1.963-.086 2.93-.266a12.248 12.248 0 003.823-1.389c.98-.567 1.86-1.288 2.61-2.136 1.252-1.418 1.998-2.997 2.553-4.4h.221c1.372 0 2.215-.549 2.68-1.009.309-.293.55-.65.707-1.046l.098-.288Z"/>"#;
    let maven_icon = r#"<path fill="currentColor" d="M12 2C6.48 2 2 6.48 2 12s4.48 10 10 10 10-4.48 10-10S17.52 2 12 2zm-1 17.93c-3.95-.49-7-3.85-7-7.93 0-.62.08-1.21.21-1.79L9 15v1c0 1.1.9 2 2 2v1.93zm6.9-2.54c-.26-.81-1-1.39-1.9-1.39h-1v-3c0-.55-.45-1-1-1H8v-2h2c.55 0 1-.45 1-1V7h2c1.1 0 2-.9 2-2v-.41c2.93 1.19 5 4.06 5 7.41 0 2.08-.8 3.97-2.1 5.39z"/>"#;
    let npm_icon = r#"<path fill="currentColor" d="M0 7.334v8h6.666v1.332H12v-1.332h12v-8H0zm6.666 6.664H5.334v-4H3.999v4H1.335V8.667h5.331v5.331zm4 0v1.336H8.001V8.667h5.334v5.332h-2.669v-.001zm12.001 0h-1.33v-4h-1.336v4h-1.335v-4h-1.33v4h-2.671V8.667h8.002v5.331zM10.665 10H12v2.667h-1.335V10z"/>"#;
    let cargo_icon = r#"<path fill="currentColor" d="M23.834 8.101a13.912 13.912 0 0 1-13.643 11.72 10.105 10.105 0 0 1-1.994-.12 6.111 6.111 0 0 1-5.082-5.761 5.934 5.934 0 0 1 11.867-.084c.025.983-.401 1.846-1.277 1.871-.936 0-1.374-.668-1.374-1.567v-2.5a1.531 1.531 0 0 0-1.52-1.533H8.715a3.648 3.648 0 1 0 2.695 6.08l.073-.11.074.121a2.58 2.58 0 0 0 2.2 1.048 2.909 2.909 0 0 0 2.695-3.04 7.912 7.912 0 0 0-.217-1.933 7.404 7.404 0 0 0-14.64 1.603 7.497 7.497 0 0 0 7.308 7.405 12.822 12.822 0 0 0 2.14-.12 11.927 11.927 0 0 0 9.98-10.023.117.117 0 0 0-.043-.117.115.115 0 0 0-.084-.023l-.09.024a.116.116 0 0 1-.147-.085.116.116 0 0 1 .054-.133zm-14.49 7.072a2.162 2.162 0 1 1 0-4.324 2.162 2.162 0 0 1 0 4.324z"/>"#;
    let pypi_icon = r#"<path fill="currentColor" d="M14.25.18l.9.2.73.26.59.3.45.32.34.34.25.34.16.33.1.3.04.26.02.2-.01.13V8.5l-.05.63-.13.55-.21.46-.26.38-.3.31-.33.25-.35.19-.35.14-.33.1-.3.07-.26.04-.21.02H8.83l-.69.05-.59.14-.5.22-.41.27-.33.32-.27.35-.2.36-.15.37-.1.35-.07.32-.04.27-.02.21v3.06H3.23l-.21-.03-.28-.07-.32-.12-.35-.18-.36-.26-.36-.36-.35-.46-.32-.59-.28-.73-.21-.88-.14-1.05L0 11.97l.06-1.22.16-1.04.24-.87.32-.71.36-.57.4-.44.42-.33.42-.24.4-.16.36-.1.32-.05.24-.01h.16l.06.01h8.16v-.83H6.24l-.01-2.75-.02-.37.05-.34.11-.31.17-.28.25-.26.31-.23.38-.2.44-.18.51-.15.58-.12.64-.1.71-.06.77-.04.84-.02 1.27.05 1.07.13zm-6.3 1.98l-.23.33-.08.41.08.41.23.34.33.22.41.09.41-.09.33-.22.23-.34.08-.41-.08-.41-.23-.33-.33-.22-.41-.09-.41.09-.33.22zM21.1 6.11l.28.06.32.12.35.18.36.27.36.35.35.47.32.59.28.73.21.88.14 1.04.05 1.23-.06 1.23-.16 1.04-.24.86-.32.71-.36.57-.4.45-.42.33-.42.24-.4.16-.36.09-.32.05-.24.02-.16-.01h-8.22v.82h5.84l.01 2.76.02.36-.05.34-.11.31-.17.29-.25.25-.31.24-.38.2-.44.17-.51.15-.58.13-.64.09-.71.07-.77.04-.84.01-1.27-.04-1.07-.14-.9-.2-.73-.25-.59-.3-.45-.33-.34-.34-.25-.34-.16-.33-.1-.3-.04-.25-.02-.2.01-.13v-5.34l.05-.64.13-.54.21-.46.26-.38.3-.32.33-.24.35-.2.35-.14.33-.1.3-.06.26-.04.21-.02.13-.01h5.84l.69-.05.59-.14.5-.21.41-.28.33-.32.27-.35.2-.36.15-.36.1-.35.07-.32.04-.28.02-.21V6.07h2.09l.14.01.21.03zm-6.47 14.25l-.23.33-.08.41.08.41.23.33.33.23.41.08.41-.08.33-.23.23-.33.08-.41-.08-.41-.23-.33-.33-.23-.41-.08-.41.08-.33.23z"/>"#;

    let nav_items = [
        (
            "dashboard",
            "/ui/",
            "Dashboard",
            r#"<path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M3 12l2-2m0 0l7-7 7 7M5 10v10a1 1 0 001 1h3m10-11l2 2m-2-2v10a1 1 0 01-1 1h-3m-6 0a1 1 0 001-1v-4a1 1 0 011-1h2a1 1 0 011 1v4a1 1 0 001 1m-6 0h6"/>"#,
            true,
        ),
        ("docker", "/ui/docker", "Docker", docker_icon, false),
        ("maven", "/ui/maven", "Maven", maven_icon, false),
        ("npm", "/ui/npm", "npm", npm_icon, false),
        ("cargo", "/ui/cargo", "Cargo", cargo_icon, false),
        ("pypi", "/ui/pypi", "PyPI", pypi_icon, false),
    ];

    let nav_html: String = nav_items.iter().map(|(id, href, label, icon_path, is_stroke)| {
        let is_active = active == *id;
        let active_class = if is_active {
            "bg-slate-700 text-white"
        } else {
            "text-slate-300 hover:bg-slate-700 hover:text-white"
        };

        let (fill_attr, stroke_attr) = if *is_stroke {
            ("none", r#" stroke="currentColor""#)
        } else {
            ("currentColor", "")
        };

        format!(r##"
            <a href="{}" class="flex items-center px-4 py-3 text-sm font-medium rounded-lg transition-colors {}">
                <svg class="w-5 h-5 mr-3" fill="{}"{} viewBox="0 0 24 24">
                    {}
                </svg>
                {}
            </a>
        "##, href, active_class, fill_attr, stroke_attr, icon_path, label)
    }).collect();

    format!(
        r#"
        <div id="sidebar" class="fixed md:static inset-y-0 left-0 z-50 w-64 bg-slate-800 text-white flex flex-col transform -translate-x-full md:translate-x-0 transition-transform duration-200 ease-in-out">
            <div class="h-16 flex items-center justify-between px-6 border-b border-slate-700">
                <div class="flex items-center">
                    <img src="{}" alt="NORA" class="h-8" />
                </div>
                <button onclick="toggleSidebar()" class="md:hidden p-1 rounded-lg hover:bg-slate-700">
                    <svg class="w-6 h-6" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                        <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M6 18L18 6M6 6l12 12"/>
                    </svg>
                </button>
            </div>
            <nav class="flex-1 px-4 py-6 space-y-1 overflow-y-auto">
                <div class="text-xs font-semibold text-slate-400 uppercase tracking-wider px-4 mb-3">
                    Navigation
                </div>
                {}
                <div class="text-xs font-semibold text-slate-400 uppercase tracking-wider px-4 mt-8 mb-3">
                    Registries
                </div>
            </nav>
            <div class="px-4 py-4 border-t border-slate-700">
                <div class="text-xs text-slate-400">
                    Nora v{}
                </div>
            </div>
        </div>
    "#,
        super::logo::LOGO_BASE64,
        nav_html,
        VERSION
    )
}

/// Dark theme header
fn header_dark() -> String {
    r##"
        <header class="h-16 bg-[#1e293b] border-b border-slate-700 flex items-center justify-between px-4 md:px-6">
            <div class="flex items-center">
                <button onclick="toggleSidebar()" class="md:hidden p-2 -ml-2 mr-2 rounded-lg hover:bg-slate-700">
                    <svg class="w-6 h-6 text-slate-300" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                        <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M4 6h16M4 12h16M4 18h16"/>
                    </svg>
                </button>
                <div class="md:hidden flex items-center">
                    <span class="font-bold text-slate-200 tracking-tight">N<span class="inline-block w-4 h-4 rounded-full border-2 border-current align-middle mx-px"></span>RA</span>
                </div>
            </div>
            <div class="flex items-center space-x-2 md:space-x-4">
                <a href="https://github.com/getnora-io/nora" target="_blank" class="p-2 text-slate-400 hover:text-slate-200 hover:bg-slate-700 rounded-lg">
                    <svg class="w-5 h-5" fill="currentColor" viewBox="0 0 24 24">
                        <path fill-rule="evenodd" d="M12 2C6.477 2 2 6.484 2 12.017c0 4.425 2.865 8.18 6.839 9.504.5.092.682-.217.682-.483 0-.237-.008-.868-.013-1.703-2.782.605-3.369-1.343-3.369-1.343-.454-1.158-1.11-1.466-1.11-1.466-.908-.62.069-.608.069-.608 1.003.07 1.531 1.032 1.531 1.032.892 1.53 2.341 1.088 2.91.832.092-.647.35-1.088.636-1.338-2.22-.253-4.555-1.113-4.555-4.951 0-1.093.39-1.988 1.029-2.688-.103-.253-.446-1.272.098-2.65 0 0 .84-.27 2.75 1.026A9.564 9.564 0 0112 6.844c.85.004 1.705.115 2.504.337 1.909-1.296 2.747-1.027 2.747-1.027.546 1.379.202 2.398.1 2.651.64.7 1.028 1.595 1.028 2.688 0 3.848-2.339 4.695-4.566 4.943.359.309.678.92.678 1.855 0 1.338-.012 2.419-.012 2.747 0 .268.18.58.688.482A10.019 10.019 0 0022 12.017C22 6.484 17.522 2 12 2z" clip-rule="evenodd"/>
                    </svg>
                </a>
                <a href="/api-docs" class="p-2 text-slate-400 hover:text-slate-200 hover:bg-slate-700 rounded-lg" title="API Docs">
                    <svg class="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                        <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 12h6m-6 4h6m2 5H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z"/>
                    </svg>
                </a>
            </div>
        </header>
    "##.to_string()
}

/// Render global stats row (5-column grid)
pub fn render_global_stats(
    downloads: u64,
    uploads: u64,
    artifacts: u64,
    cache_hit_percent: f64,
    storage_bytes: u64,
) -> String {
    format!(
        r##"
        <div class="grid grid-cols-2 md:grid-cols-3 lg:grid-cols-5 gap-4 mb-6">
            <div class="bg-[#1e293b] rounded-lg p-4 border border-slate-700">
                <div class="text-slate-400 text-sm mb-1">Downloads</div>
                <div id="stat-downloads" class="text-2xl font-bold text-slate-200">{}</div>
            </div>
            <div class="bg-[#1e293b] rounded-lg p-4 border border-slate-700">
                <div class="text-slate-400 text-sm mb-1">Uploads</div>
                <div id="stat-uploads" class="text-2xl font-bold text-slate-200">{}</div>
            </div>
            <div class="bg-[#1e293b] rounded-lg p-4 border border-slate-700">
                <div class="text-slate-400 text-sm mb-1">Artifacts</div>
                <div id="stat-artifacts" class="text-2xl font-bold text-slate-200">{}</div>
            </div>
            <div class="bg-[#1e293b] rounded-lg p-4 border border-slate-700">
                <div class="text-slate-400 text-sm mb-1">Cache Hit</div>
                <div id="stat-cache-hit" class="text-2xl font-bold text-slate-200">{:.1}%</div>
            </div>
            <div class="bg-[#1e293b] rounded-lg p-4 border border-slate-700">
                <div class="text-slate-400 text-sm mb-1">Storage</div>
                <div id="stat-storage" class="text-2xl font-bold text-slate-200">{}</div>
            </div>
        </div>
        "##,
        downloads,
        uploads,
        artifacts,
        cache_hit_percent,
        format_size(storage_bytes)
    )
}

/// Render registry card with extended metrics
pub fn render_registry_card(
    name: &str,
    icon_path: &str,
    artifact_count: usize,
    downloads: u64,
    uploads: u64,
    size_bytes: u64,
    href: &str,
) -> String {
    format!(
        r##"
        <a href="{}" id="registry-{}" class="block bg-[#1e293b] rounded-lg border border-slate-700 p-4 md:p-6 hover:border-blue-400 transition-all">
            <div class="flex items-center justify-between mb-3">
                <svg class="w-8 h-8 text-slate-400" fill="currentColor" viewBox="0 0 24 24">
                    {}
                </svg>
                <span class="text-xs font-medium text-green-400 bg-green-400/10 px-2 py-1 rounded-full">ACTIVE</span>
            </div>
            <div class="text-lg font-semibold text-slate-200 mb-2">{}</div>
            <div class="grid grid-cols-2 gap-2 text-sm">
                <div>
                    <span class="text-slate-500">Artifacts</span>
                    <div class="text-slate-300 font-medium">{}</div>
                </div>
                <div>
                    <span class="text-slate-500">Size</span>
                    <div class="text-slate-300 font-medium">{}</div>
                </div>
                <div>
                    <span class="text-slate-500">Downloads</span>
                    <div class="text-slate-300 font-medium">{}</div>
                </div>
                <div>
                    <span class="text-slate-500">Uploads</span>
                    <div class="text-slate-300 font-medium">{}</div>
                </div>
            </div>
        </a>
        "##,
        href,
        name.to_lowercase(),
        icon_path,
        name,
        artifact_count,
        format_size(size_bytes),
        downloads,
        uploads
    )
}

/// Render mount points table
pub fn render_mount_points_table(mount_points: &[(String, String, Option<String>)]) -> String {
    let rows: String = mount_points
        .iter()
        .map(|(registry, mount_path, proxy)| {
            let proxy_display = proxy.as_deref().unwrap_or("-");
            format!(
                r##"
                <tr class="border-b border-slate-700">
                    <td class="py-3 text-slate-300">{}</td>
                    <td class="py-3 font-mono text-blue-400">{}</td>
                    <td class="py-3 text-slate-400">{}</td>
                </tr>
                "##,
                registry, mount_path, proxy_display
            )
        })
        .collect();

    format!(
        r##"
        <div class="bg-[#1e293b] rounded-lg border border-slate-700 overflow-hidden">
            <div class="px-4 py-3 border-b border-slate-700">
                <h3 class="text-slate-200 font-semibold">Mount Points</h3>
            </div>
            <table class="w-full">
                <thead>
                    <tr class="text-left text-xs text-slate-500 uppercase border-b border-slate-700">
                        <th class="px-4 py-2">Registry</th>
                        <th class="px-4 py-2">Mount Path</th>
                        <th class="px-4 py-2">Proxy Upstream</th>
                    </tr>
                </thead>
                <tbody class="px-4">
                    {}
                </tbody>
            </table>
        </div>
        "##,
        rows
    )
}

/// Render a single activity log row
pub fn render_activity_row(
    timestamp: &str,
    action: &str,
    artifact: &str,
    registry: &str,
    source: &str,
) -> String {
    let action_color = match action {
        "PULL" => "text-blue-400",
        "PUSH" => "text-green-400",
        "CACHE" => "text-yellow-400",
        "PROXY" => "text-purple-400",
        _ => "text-slate-400",
    };

    format!(
        r##"
        <tr class="border-b border-slate-700/50 text-sm">
            <td class="py-2 text-slate-500">{}</td>
            <td class="py-2 font-medium {}"><span class="px-2 py-0.5 bg-slate-700 rounded">{}</span></td>
            <td class="py-2 text-slate-300 font-mono text-xs">{}</td>
            <td class="py-2 text-slate-400">{}</td>
            <td class="py-2 text-slate-500">{}</td>
        </tr>
        "##,
        timestamp,
        action_color,
        action,
        html_escape(artifact),
        registry,
        source
    )
}

/// Render the activity log container
pub fn render_activity_log(rows: &str) -> String {
    format!(
        r##"
        <div class="bg-[#1e293b] rounded-lg border border-slate-700 overflow-hidden">
            <div class="px-4 py-3 border-b border-slate-700">
                <h3 class="text-slate-200 font-semibold">Recent Activity</h3>
            </div>
            <div class="overflow-x-auto">
                <table class="w-full" id="activity-log">
                    <thead>
                        <tr class="text-left text-xs text-slate-500 uppercase border-b border-slate-700">
                            <th class="px-4 py-2">Time</th>
                            <th class="px-4 py-2">Action</th>
                            <th class="px-4 py-2">Artifact</th>
                            <th class="px-4 py-2">Registry</th>
                            <th class="px-4 py-2">Source</th>
                        </tr>
                    </thead>
                    <tbody class="px-4">
                        {}
                    </tbody>
                </table>
            </div>
        </div>
        "##,
        rows
    )
}

/// Render the polling script for auto-refresh
pub fn render_polling_script() -> String {
    r##"
    <script>
        setInterval(async () => {
            try {
                const data = await fetch('/api/ui/dashboard').then(r => r.json());

                // Update global stats
                document.getElementById('stat-downloads').textContent = data.global_stats.downloads;
                document.getElementById('stat-uploads').textContent = data.global_stats.uploads;
                document.getElementById('stat-artifacts').textContent = data.global_stats.artifacts;
                document.getElementById('stat-cache-hit').textContent = data.global_stats.cache_hit_percent.toFixed(1) + '%';

                // Format storage size
                const bytes = data.global_stats.storage_bytes;
                let sizeStr;
                if (bytes >= 1073741824) sizeStr = (bytes / 1073741824).toFixed(1) + ' GB';
                else if (bytes >= 1048576) sizeStr = (bytes / 1048576).toFixed(1) + ' MB';
                else if (bytes >= 1024) sizeStr = (bytes / 1024).toFixed(1) + ' KB';
                else sizeStr = bytes + ' B';
                document.getElementById('stat-storage').textContent = sizeStr;

                // Update uptime
                const uptime = document.getElementById('uptime');
                if (uptime) {
                    const secs = data.uptime_seconds;
                    const hours = Math.floor(secs / 3600);
                    const mins = Math.floor((secs % 3600) / 60);
                    uptime.textContent = hours + 'h ' + mins + 'm';
                }
            } catch (e) {
                console.error('Dashboard poll failed:', e);
            }
        }, 5000);
    </script>
    "##.to_string()
}

/// Sidebar navigation component (light theme, unused)
#[allow(dead_code)]
fn sidebar(active_page: Option<&str>) -> String {
    let active = active_page.unwrap_or("");

    // SVG icon paths for registries (Simple Icons style)
    let docker_icon = r#"<path fill="currentColor" d="M13.983 11.078h2.119a.186.186 0 00.186-.185V9.006a.186.186 0 00-.186-.186h-2.119a.185.185 0 00-.185.185v1.888c0 .102.083.185.185.185m-2.954-5.43h2.118a.186.186 0 00.186-.186V3.574a.186.186 0 00-.186-.185h-2.118a.185.185 0 00-.185.185v1.888c0 .102.082.185.185.186m0 2.716h2.118a.187.187 0 00.186-.186V6.29a.186.186 0 00-.186-.185h-2.118a.185.185 0 00-.185.185v1.887c0 .102.082.185.185.186m-2.93 0h2.12a.186.186 0 00.184-.186V6.29a.185.185 0 00-.185-.185H8.1a.185.185 0 00-.185.185v1.887c0 .102.083.185.185.186m-2.964 0h2.119a.186.186 0 00.185-.186V6.29a.185.185 0 00-.185-.185H5.136a.186.186 0 00-.186.185v1.887c0 .102.084.185.186.186m5.893 2.715h2.118a.186.186 0 00.186-.185V9.006a.186.186 0 00-.186-.186h-2.118a.185.185 0 00-.185.185v1.888c0 .102.082.185.185.185m-2.93 0h2.12a.185.185 0 00.184-.185V9.006a.185.185 0 00-.184-.186h-2.12a.185.185 0 00-.184.185v1.888c0 .102.083.185.185.185m-2.964 0h2.119a.185.185 0 00.185-.185V9.006a.185.185 0 00-.185-.186h-2.12a.186.186 0 00-.185.186v1.887c0 .102.084.185.186.185m-2.92 0h2.12a.185.185 0 00.184-.185V9.006a.185.185 0 00-.184-.186h-2.12a.185.185 0 00-.184.185v1.888c0 .102.082.185.185.185M23.763 9.89c-.065-.051-.672-.51-1.954-.51-.338.001-.676.03-1.01.087-.248-1.7-1.653-2.53-1.716-2.566l-.344-.199-.226.327c-.284.438-.49.922-.612 1.43-.23.97-.09 1.882.403 2.661-.595.332-1.55.413-1.744.42H.751a.751.751 0 00-.75.748 11.376 11.376 0 00.692 4.062c.545 1.428 1.355 2.48 2.41 3.124 1.18.723 3.1 1.137 5.275 1.137.983.003 1.963-.086 2.93-.266a12.248 12.248 0 003.823-1.389c.98-.567 1.86-1.288 2.61-2.136 1.252-1.418 1.998-2.997 2.553-4.4h.221c1.372 0 2.215-.549 2.68-1.009.309-.293.55-.65.707-1.046l.098-.288Z"/>"#;
    let maven_icon = r#"<path fill="currentColor" d="M12 2C6.48 2 2 6.48 2 12s4.48 10 10 10 10-4.48 10-10S17.52 2 12 2zm-1 17.93c-3.95-.49-7-3.85-7-7.93 0-.62.08-1.21.21-1.79L9 15v1c0 1.1.9 2 2 2v1.93zm6.9-2.54c-.26-.81-1-1.39-1.9-1.39h-1v-3c0-.55-.45-1-1-1H8v-2h2c.55 0 1-.45 1-1V7h2c1.1 0 2-.9 2-2v-.41c2.93 1.19 5 4.06 5 7.41 0 2.08-.8 3.97-2.1 5.39z"/>"#;
    let npm_icon = r#"<path fill="currentColor" d="M0 7.334v8h6.666v1.332H12v-1.332h12v-8H0zm6.666 6.664H5.334v-4H3.999v4H1.335V8.667h5.331v5.331zm4 0v1.336H8.001V8.667h5.334v5.332h-2.669v-.001zm12.001 0h-1.33v-4h-1.336v4h-1.335v-4h-1.33v4h-2.671V8.667h8.002v5.331zM10.665 10H12v2.667h-1.335V10z"/>"#;
    let cargo_icon = r#"<path fill="currentColor" d="M23.834 8.101a13.912 13.912 0 0 1-13.643 11.72 10.105 10.105 0 0 1-1.994-.12 6.111 6.111 0 0 1-5.082-5.761 5.934 5.934 0 0 1 11.867-.084c.025.983-.401 1.846-1.277 1.871-.936 0-1.374-.668-1.374-1.567v-2.5a1.531 1.531 0 0 0-1.52-1.533H8.715a3.648 3.648 0 1 0 2.695 6.08l.073-.11.074.121a2.58 2.58 0 0 0 2.2 1.048 2.909 2.909 0 0 0 2.695-3.04 7.912 7.912 0 0 0-.217-1.933 7.404 7.404 0 0 0-14.64 1.603 7.497 7.497 0 0 0 7.308 7.405 12.822 12.822 0 0 0 2.14-.12 11.927 11.927 0 0 0 9.98-10.023.117.117 0 0 0-.043-.117.115.115 0 0 0-.084-.023l-.09.024a.116.116 0 0 1-.147-.085.116.116 0 0 1 .054-.133zm-14.49 7.072a2.162 2.162 0 1 1 0-4.324 2.162 2.162 0 0 1 0 4.324z"/>"#;
    let pypi_icon = r#"<path fill="currentColor" d="M14.25.18l.9.2.73.26.59.3.45.32.34.34.25.34.16.33.1.3.04.26.02.2-.01.13V8.5l-.05.63-.13.55-.21.46-.26.38-.3.31-.33.25-.35.19-.35.14-.33.1-.3.07-.26.04-.21.02H8.83l-.69.05-.59.14-.5.22-.41.27-.33.32-.27.35-.2.36-.15.37-.1.35-.07.32-.04.27-.02.21v3.06H3.23l-.21-.03-.28-.07-.32-.12-.35-.18-.36-.26-.36-.36-.35-.46-.32-.59-.28-.73-.21-.88-.14-1.05L0 11.97l.06-1.22.16-1.04.24-.87.32-.71.36-.57.4-.44.42-.33.42-.24.4-.16.36-.1.32-.05.24-.01h.16l.06.01h8.16v-.83H6.24l-.01-2.75-.02-.37.05-.34.11-.31.17-.28.25-.26.31-.23.38-.2.44-.18.51-.15.58-.12.64-.1.71-.06.77-.04.84-.02 1.27.05 1.07.13zm-6.3 1.98l-.23.33-.08.41.08.41.23.34.33.22.41.09.41-.09.33-.22.23-.34.08-.41-.08-.41-.23-.33-.33-.22-.41-.09-.41.09-.33.22zM21.1 6.11l.28.06.32.12.35.18.36.27.36.35.35.47.32.59.28.73.21.88.14 1.04.05 1.23-.06 1.23-.16 1.04-.24.86-.32.71-.36.57-.4.45-.42.33-.42.24-.4.16-.36.09-.32.05-.24.02-.16-.01h-8.22v.82h5.84l.01 2.76.02.36-.05.34-.11.31-.17.29-.25.25-.31.24-.38.2-.44.17-.51.15-.58.13-.64.09-.71.07-.77.04-.84.01-1.27-.04-1.07-.14-.9-.2-.73-.25-.59-.3-.45-.33-.34-.34-.25-.34-.16-.33-.1-.3-.04-.25-.02-.2.01-.13v-5.34l.05-.64.13-.54.21-.46.26-.38.3-.32.33-.24.35-.2.35-.14.33-.1.3-.06.26-.04.21-.02.13-.01h5.84l.69-.05.59-.14.5-.21.41-.28.33-.32.27-.35.2-.36.15-.36.1-.35.07-.32.04-.28.02-.21V6.07h2.09l.14.01.21.03zm-6.47 14.25l-.23.33-.08.41.08.41.23.33.33.23.41.08.41-.08.33-.23.23-.33.08-.41-.08-.41-.23-.33-.33-.23-.41-.08-.41.08-.33.23z"/>"#;

    let nav_items = [
        (
            "dashboard",
            "/ui/",
            "Dashboard",
            r#"<path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M3 12l2-2m0 0l7-7 7 7M5 10v10a1 1 0 001 1h3m10-11l2 2m-2-2v10a1 1 0 01-1 1h-3m-6 0a1 1 0 001-1v-4a1 1 0 011-1h2a1 1 0 011 1v4a1 1 0 001 1m-6 0h6"/>"#,
            true, // stroke icon
        ),
        ("docker", "/ui/docker", "Docker", docker_icon, false),
        ("maven", "/ui/maven", "Maven", maven_icon, false),
        ("npm", "/ui/npm", "npm", npm_icon, false),
        ("cargo", "/ui/cargo", "Cargo", cargo_icon, false),
        ("pypi", "/ui/pypi", "PyPI", pypi_icon, false),
    ];

    let nav_html: String = nav_items.iter().map(|(id, href, label, icon_path, is_stroke)| {
        let is_active = active == *id;
        let active_class = if is_active {
            "bg-slate-700 text-white"
        } else {
            "text-slate-300 hover:bg-slate-700 hover:text-white"
        };

        // SVG attributes differ for stroke vs fill icons
        let (fill_attr, stroke_attr) = if *is_stroke {
            ("none", r#" stroke="currentColor""#)
        } else {
            ("currentColor", "")
        };

        format!(r##"
            <a href="{}" class="flex items-center px-4 py-3 text-sm font-medium rounded-lg transition-colors {}">
                <svg class="w-5 h-5 mr-3" fill="{}"{} viewBox="0 0 24 24">
                    {}
                </svg>
                {}
            </a>
        "##, href, active_class, fill_attr, stroke_attr, icon_path, label)
    }).collect();

    format!(
        r#"
        <div id="sidebar" class="fixed md:static inset-y-0 left-0 z-50 w-64 bg-slate-800 text-white flex flex-col transform -translate-x-full md:translate-x-0 transition-transform duration-200 ease-in-out">
            <!-- Logo -->
            <div class="h-16 flex items-center justify-between px-6 border-b border-slate-700">
                <div class="flex items-center">
                    <img src="{}" alt="NORA" class="h-8" />
                </div>
                <!-- Close button (mobile only) -->
                <button onclick="toggleSidebar()" class="md:hidden p-1 rounded-lg hover:bg-slate-700">
                    <svg class="w-6 h-6" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                        <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M6 18L18 6M6 6l12 12"/>
                    </svg>
                </button>
            </div>

            <!-- Navigation -->
            <nav class="flex-1 px-4 py-6 space-y-1 overflow-y-auto">
                <div class="text-xs font-semibold text-slate-400 uppercase tracking-wider px-4 mb-3">
                    Navigation
                </div>
                {}

                <div class="text-xs font-semibold text-slate-400 uppercase tracking-wider px-4 mt-8 mb-3">
                    Registries
                </div>
            </nav>

            <!-- Footer -->
            <div class="px-4 py-4 border-t border-slate-700">
                <div class="text-xs text-slate-400">
                    Nora v{}
                </div>
            </div>
        </div>
    "#,
        super::logo::LOGO_BASE64,
        nav_html,
        VERSION
    )
}

/// Header component (light theme, unused)
#[allow(dead_code)]
fn header() -> String {
    r##"
        <header class="h-16 bg-white border-b border-slate-200 flex items-center justify-between px-4 md:px-6">
            <div class="flex items-center">
                <!-- Hamburger menu (mobile only) -->
                <button onclick="toggleSidebar()" class="md:hidden p-2 -ml-2 mr-2 rounded-lg hover:bg-slate-100">
                    <svg class="w-6 h-6 text-slate-600" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                        <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M4 6h16M4 12h16M4 18h16"/>
                    </svg>
                </button>
                <!-- Mobile logo -->
                <div class="md:hidden flex items-center">
                    <span class="font-bold text-slate-800 tracking-tight">N<span class="inline-block w-4 h-4 rounded-full border-2 border-current align-middle mx-px"></span>RA</span>
                </div>
            </div>
            <div class="flex items-center space-x-2 md:space-x-4">
                <a href="https://github.com/getnora-io/nora" target="_blank" class="p-2 text-slate-500 hover:text-slate-700 hover:bg-slate-100 rounded-lg">
                    <svg class="w-5 h-5" fill="currentColor" viewBox="0 0 24 24">
                        <path fill-rule="evenodd" d="M12 2C6.477 2 2 6.484 2 12.017c0 4.425 2.865 8.18 6.839 9.504.5.092.682-.217.682-.483 0-.237-.008-.868-.013-1.703-2.782.605-3.369-1.343-3.369-1.343-.454-1.158-1.11-1.466-1.11-1.466-.908-.62.069-.608.069-.608 1.003.07 1.531 1.032 1.531 1.032.892 1.53 2.341 1.088 2.91.832.092-.647.35-1.088.636-1.338-2.22-.253-4.555-1.113-4.555-4.951 0-1.093.39-1.988 1.029-2.688-.103-.253-.446-1.272.098-2.65 0 0 .84-.27 2.75 1.026A9.564 9.564 0 0112 6.844c.85.004 1.705.115 2.504.337 1.909-1.296 2.747-1.027 2.747-1.027.546 1.379.202 2.398.1 2.651.64.7 1.028 1.595 1.028 2.688 0 3.848-2.339 4.695-4.566 4.943.359.309.678.92.678 1.855 0 1.338-.012 2.419-.012 2.747 0 .268.18.58.688.482A10.019 10.019 0 0022 12.017C22 6.484 17.522 2 12 2z" clip-rule="evenodd"/>
                    </svg>
                </a>
                <a href="/api-docs" class="p-2 text-slate-500 hover:text-slate-700 hover:bg-slate-100 rounded-lg" title="API Docs">
                    <svg class="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                        <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 12h6m-6 4h6m2 5H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z"/>
                    </svg>
                </a>
            </div>
        </header>
    "##.to_string()
}

/// SVG icon definitions for registries (exported for use in templates)
pub mod icons {
    pub const DOCKER: &str = r#"<path fill="currentColor" d="M13.983 11.078h2.119a.186.186 0 00.186-.185V9.006a.186.186 0 00-.186-.186h-2.119a.185.185 0 00-.185.185v1.888c0 .102.083.185.185.185m-2.954-5.43h2.118a.186.186 0 00.186-.186V3.574a.186.186 0 00-.186-.185h-2.118a.185.185 0 00-.185.185v1.888c0 .102.082.185.185.186m0 2.716h2.118a.187.187 0 00.186-.186V6.29a.186.186 0 00-.186-.185h-2.118a.185.185 0 00-.185.185v1.887c0 .102.082.185.185.186m-2.93 0h2.12a.186.186 0 00.184-.186V6.29a.185.185 0 00-.185-.185H8.1a.185.185 0 00-.185.185v1.887c0 .102.083.185.185.186m-2.964 0h2.119a.186.186 0 00.185-.186V6.29a.185.185 0 00-.185-.185H5.136a.186.186 0 00-.186.185v1.887c0 .102.084.185.186.186m5.893 2.715h2.118a.186.186 0 00.186-.185V9.006a.186.186 0 00-.186-.186h-2.118a.185.185 0 00-.185.185v1.888c0 .102.082.185.185.185m-2.93 0h2.12a.185.185 0 00.184-.185V9.006a.185.185 0 00-.184-.186h-2.12a.185.185 0 00-.184.185v1.888c0 .102.083.185.185.185m-2.964 0h2.119a.185.185 0 00.185-.185V9.006a.185.185 0 00-.185-.186h-2.12a.186.186 0 00-.185.186v1.887c0 .102.084.185.186.185m-2.92 0h2.12a.185.185 0 00.184-.185V9.006a.185.185 0 00-.184-.186h-2.12a.185.185 0 00-.184.185v1.888c0 .102.082.185.185.185M23.763 9.89c-.065-.051-.672-.51-1.954-.51-.338.001-.676.03-1.01.087-.248-1.7-1.653-2.53-1.716-2.566l-.344-.199-.226.327c-.284.438-.49.922-.612 1.43-.23.97-.09 1.882.403 2.661-.595.332-1.55.413-1.744.42H.751a.751.751 0 00-.75.748 11.376 11.376 0 00.692 4.062c.545 1.428 1.355 2.48 2.41 3.124 1.18.723 3.1 1.137 5.275 1.137.983.003 1.963-.086 2.93-.266a12.248 12.248 0 003.823-1.389c.98-.567 1.86-1.288 2.61-2.136 1.252-1.418 1.998-2.997 2.553-4.4h.221c1.372 0 2.215-.549 2.68-1.009.309-.293.55-.65.707-1.046l.098-.288Z"/>"#;
    pub const MAVEN: &str = r#"<path fill="currentColor" d="M12 2C6.48 2 2 6.48 2 12s4.48 10 10 10 10-4.48 10-10S17.52 2 12 2zm-1 17.93c-3.95-.49-7-3.85-7-7.93 0-.62.08-1.21.21-1.79L9 15v1c0 1.1.9 2 2 2v1.93zm6.9-2.54c-.26-.81-1-1.39-1.9-1.39h-1v-3c0-.55-.45-1-1-1H8v-2h2c.55 0 1-.45 1-1V7h2c1.1 0 2-.9 2-2v-.41c2.93 1.19 5 4.06 5 7.41 0 2.08-.8 3.97-2.1 5.39z"/>"#;
    pub const NPM: &str = r#"<path fill="currentColor" d="M0 7.334v8h6.666v1.332H12v-1.332h12v-8H0zm6.666 6.664H5.334v-4H3.999v4H1.335V8.667h5.331v5.331zm4 0v1.336H8.001V8.667h5.334v5.332h-2.669v-.001zm12.001 0h-1.33v-4h-1.336v4h-1.335v-4h-1.33v4h-2.671V8.667h8.002v5.331zM10.665 10H12v2.667h-1.335V10z"/>"#;
    pub const CARGO: &str = r#"<path fill="currentColor" d="M23.834 8.101a13.912 13.912 0 0 1-13.643 11.72 10.105 10.105 0 0 1-1.994-.12 6.111 6.111 0 0 1-5.082-5.761 5.934 5.934 0 0 1 11.867-.084c.025.983-.401 1.846-1.277 1.871-.936 0-1.374-.668-1.374-1.567v-2.5a1.531 1.531 0 0 0-1.52-1.533H8.715a3.648 3.648 0 1 0 2.695 6.08l.073-.11.074.121a2.58 2.58 0 0 0 2.2 1.048 2.909 2.909 0 0 0 2.695-3.04 7.912 7.912 0 0 0-.217-1.933 7.404 7.404 0 0 0-14.64 1.603 7.497 7.497 0 0 0 7.308 7.405 12.822 12.822 0 0 0 2.14-.12 11.927 11.927 0 0 0 9.98-10.023.117.117 0 0 0-.043-.117.115.115 0 0 0-.084-.023l-.09.024a.116.116 0 0 1-.147-.085.116.116 0 0 1 .054-.133zm-14.49 7.072a2.162 2.162 0 1 1 0-4.324 2.162 2.162 0 0 1 0 4.324z"/>"#;
    pub const PYPI: &str = r#"<path fill="currentColor" d="M14.25.18l.9.2.73.26.59.3.45.32.34.34.25.34.16.33.1.3.04.26.02.2-.01.13V8.5l-.05.63-.13.55-.21.46-.26.38-.3.31-.33.25-.35.19-.35.14-.33.1-.3.07-.26.04-.21.02H8.83l-.69.05-.59.14-.5.22-.41.27-.33.32-.27.35-.2.36-.15.37-.1.35-.07.32-.04.27-.02.21v3.06H3.23l-.21-.03-.28-.07-.32-.12-.35-.18-.36-.26-.36-.36-.35-.46-.32-.59-.28-.73-.21-.88-.14-1.05L0 11.97l.06-1.22.16-1.04.24-.87.32-.71.36-.57.4-.44.42-.33.42-.24.4-.16.36-.1.32-.05.24-.01h.16l.06.01h8.16v-.83H6.24l-.01-2.75-.02-.37.05-.34.11-.31.17-.28.25-.26.31-.23.38-.2.44-.18.51-.15.58-.12.64-.1.71-.06.77-.04.84-.02 1.27.05 1.07.13zm-6.3 1.98l-.23.33-.08.41.08.41.23.34.33.22.41.09.41-.09.33-.22.23-.34.08-.41-.08-.41-.23-.33-.33-.22-.41-.09-.41.09-.33.22zM21.1 6.11l.28.06.32.12.35.18.36.27.36.35.35.47.32.59.28.73.21.88.14 1.04.05 1.23-.06 1.23-.16 1.04-.24.86-.32.71-.36.57-.4.45-.42.33-.42.24-.4.16-.36.09-.32.05-.24.02-.16-.01h-8.22v.82h5.84l.01 2.76.02.36-.05.34-.11.31-.17.29-.25.25-.31.24-.38.2-.44.17-.51.15-.58.13-.64.09-.71.07-.77.04-.84.01-1.27-.04-1.07-.14-.9-.2-.73-.25-.59-.3-.45-.33-.34-.34-.25-.34-.16-.33-.1-.3-.04-.25-.02-.2.01-.13v-5.34l.05-.64.13-.54.21-.46.26-.38.3-.32.33-.24.35-.2.35-.14.33-.1.3-.06.26-.04.21-.02.13-.01h5.84l.69-.05.59-.14.5-.21.41-.28.33-.32.27-.35.2-.36.15-.36.1-.35.07-.32.04-.28.02-.21V6.07h2.09l.14.01.21.03zm-6.47 14.25l-.23.33-.08.41.08.41.23.33.33.23.41.08.41-.08.33-.23.23-.33.08-.41-.08-.41-.23-.33-.33-.23-.41-.08-.41.08-.33.23z"/>"#;
}

/// Stat card for dashboard with SVG icon (used in light theme pages)
#[allow(dead_code)]
pub fn stat_card(name: &str, icon_path: &str, count: usize, href: &str, unit: &str) -> String {
    format!(
        r##"
        <a href="{}" class="block bg-white rounded-lg shadow-sm border border-slate-200 p-4 md:p-6 hover:shadow-md hover:border-blue-300 active:bg-slate-50 transition-all touch-manipulation">
            <div class="flex items-center justify-between mb-3 md:mb-4">
                <svg class="w-8 h-8 md:w-10 md:h-10 text-slate-600" fill="currentColor" viewBox="0 0 24 24">
                    {}
                </svg>
                <span class="text-xs font-medium text-green-600 bg-green-100 px-2 py-1 rounded-full">ACTIVE</span>
            </div>
            <div class="text-base md:text-lg font-semibold text-slate-800 mb-1">{}</div>
            <div class="text-xl md:text-2xl font-bold text-slate-800">{}</div>
            <div class="text-sm text-slate-500">{}</div>
        </a>
    "##,
        href, icon_path, name, count, unit
    )
}

/// Format file size in human-readable format
pub fn format_size(bytes: u64) -> String {
    const KB: u64 = 1024;
    const MB: u64 = KB * 1024;
    const GB: u64 = MB * 1024;

    if bytes >= GB {
        format!("{:.1} GB", bytes as f64 / GB as f64)
    } else if bytes >= MB {
        format!("{:.1} MB", bytes as f64 / MB as f64)
    } else if bytes >= KB {
        format!("{:.1} KB", bytes as f64 / KB as f64)
    } else {
        format!("{} B", bytes)
    }
}

/// Escape HTML special characters
pub fn html_escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&#39;")
}

/// Format Unix timestamp as relative time
pub fn format_timestamp(ts: u64) -> String {
    if ts == 0 {
        return "N/A".to_string();
    }

    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);

    if now < ts {
        return "just now".to_string();
    }

    let diff = now - ts;

    if diff < 60 {
        "just now".to_string()
    } else if diff < 3600 {
        let mins = diff / 60;
        format!("{} min{} ago", mins, if mins == 1 { "" } else { "s" })
    } else if diff < 86400 {
        let hours = diff / 3600;
        format!("{} hour{} ago", hours, if hours == 1 { "" } else { "s" })
    } else if diff < 604800 {
        let days = diff / 86400;
        format!("{} day{} ago", days, if days == 1 { "" } else { "s" })
    } else if diff < 2592000 {
        let weeks = diff / 604800;
        format!("{} week{} ago", weeks, if weeks == 1 { "" } else { "s" })
    } else {
        let months = diff / 2592000;
        format!("{} month{} ago", months, if months == 1 { "" } else { "s" })
    }
}
