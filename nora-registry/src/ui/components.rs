/// Main layout wrapper with header and sidebar
pub fn layout(title: &str, content: &str, active_page: Option<&str>) -> String {
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
    </style>
</head>
<body class="bg-slate-100 min-h-screen">
    <div class="flex h-screen overflow-hidden">
        <!-- Sidebar -->
        {}

        <!-- Main content -->
        <div class="flex-1 flex flex-col overflow-hidden">
            <!-- Header -->
            {}

            <!-- Content -->
            <main class="flex-1 overflow-y-auto p-6">
                {}
            </main>
        </div>
    </div>
</body>
</html>"##,
        html_escape(title),
        sidebar(active_page),
        header(),
        content
    )
}

/// Sidebar navigation component
fn sidebar(active_page: Option<&str>) -> String {
    let active = active_page.unwrap_or("");

    let nav_items = [
        (
            "dashboard",
            "/ui/",
            "Dashboard",
            r#"<path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M3 12l2-2m0 0l7-7 7 7M5 10v10a1 1 0 001 1h3m10-11l2 2m-2-2v10a1 1 0 01-1 1h-3m-6 0a1 1 0 001-1v-4a1 1 0 011-1h2a1 1 0 011 1v4a1 1 0 001 1m-6 0h6"/>"#,
        ),
        ("docker", "/ui/docker", "🐳 Docker", ""),
        ("maven", "/ui/maven", "☕ Maven", ""),
        ("npm", "/ui/npm", "📦 npm", ""),
        ("cargo", "/ui/cargo", "🦀 Cargo", ""),
        ("pypi", "/ui/pypi", "🐍 PyPI", ""),
    ];

    let nav_html: String = nav_items.iter().map(|(id, href, label, icon_path)| {
        let is_active = active == *id;
        let active_class = if is_active {
            "bg-slate-700 text-white"
        } else {
            "text-slate-300 hover:bg-slate-700 hover:text-white"
        };

        if icon_path.is_empty() {
            // Emoji-based item
            format!(r#"
                <a href="{}" class="flex items-center px-4 py-3 text-sm font-medium rounded-lg transition-colors {}">
                    <span class="mr-3 text-lg">{}</span>
                </a>
            "#, href, active_class, label)
        } else {
            // SVG icon item
            format!(r##"
                <a href="{}" class="flex items-center px-4 py-3 text-sm font-medium rounded-lg transition-colors {}">
                    <svg class="w-5 h-5 mr-3" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                        {}
                    </svg>
                    {}
                </a>
            "##, href, active_class, icon_path, label)
        }
    }).collect();

    format!(
        r#"
        <div class="w-64 bg-slate-800 text-white flex flex-col">
            <!-- Logo -->
            <div class="h-16 flex items-center px-6 border-b border-slate-700">
                <span class="text-2xl mr-2">⚓</span>
                <span class="text-xl font-bold">Nora</span>
            </div>

            <!-- Navigation -->
            <nav class="flex-1 px-4 py-6 space-y-1">
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
                    Nora v0.1.0
                </div>
            </div>
        </div>
    "#,
        nav_html
    )
}

/// Header component
fn header() -> String {
    r##"
        <header class="h-16 bg-white border-b border-slate-200 flex items-center justify-between px-6">
            <div class="flex-1">
                <!-- Search removed for simplicity, HTMX search is on list pages -->
            </div>
            <div class="flex items-center space-x-4">
                <a href="https://github.com" target="_blank" class="text-slate-500 hover:text-slate-700">
                    <svg class="w-5 h-5" fill="currentColor" viewBox="0 0 24 24">
                        <path fill-rule="evenodd" d="M12 2C6.477 2 2 6.484 2 12.017c0 4.425 2.865 8.18 6.839 9.504.5.092.682-.217.682-.483 0-.237-.008-.868-.013-1.703-2.782.605-3.369-1.343-3.369-1.343-.454-1.158-1.11-1.466-1.11-1.466-.908-.62.069-.608.069-.608 1.003.07 1.531 1.032 1.531 1.032.892 1.53 2.341 1.088 2.91.832.092-.647.35-1.088.636-1.338-2.22-.253-4.555-1.113-4.555-4.951 0-1.093.39-1.988 1.029-2.688-.103-.253-.446-1.272.098-2.65 0 0 .84-.27 2.75 1.026A9.564 9.564 0 0112 6.844c.85.004 1.705.115 2.504.337 1.909-1.296 2.747-1.027 2.747-1.027.546 1.379.202 2.398.1 2.651.64.7 1.028 1.595 1.028 2.688 0 3.848-2.339 4.695-4.566 4.943.359.309.678.92.678 1.855 0 1.338-.012 2.419-.012 2.747 0 .268.18.58.688.482A10.019 10.019 0 0022 12.017C22 6.484 17.522 2 12 2z" clip-rule="evenodd"/>
                    </svg>
                </a>
                <button class="text-slate-500 hover:text-slate-700">
                    <svg class="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                        <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M8.228 9c.549-1.165 2.03-2 3.772-2 2.21 0 4 1.343 4 3 0 1.4-1.278 2.575-3.006 2.907-.542.104-.994.54-.994 1.093m0 3h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z"/>
                    </svg>
                </button>
            </div>
        </header>
    "##.to_string()
}

/// Stat card for dashboard
pub fn stat_card(name: &str, icon: &str, count: usize, href: &str, unit: &str) -> String {
    format!(
        r##"
        <a href="{}" class="bg-white rounded-lg shadow-sm border border-slate-200 p-6 hover:shadow-md hover:border-blue-300 transition-all">
            <div class="flex items-center justify-between mb-4">
                <span class="text-3xl">{}</span>
                <span class="text-xs font-medium text-green-600 bg-green-100 px-2 py-1 rounded-full">ACTIVE</span>
            </div>
            <div class="text-lg font-semibold text-slate-800 mb-1">{}</div>
            <div class="text-2xl font-bold text-slate-800">{}</div>
            <div class="text-sm text-slate-500">{}</div>
        </a>
    "##,
        href, icon, name, count, unit
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
