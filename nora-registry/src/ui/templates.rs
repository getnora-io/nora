// Copyright (c) 2026 The NORA Authors
// SPDX-License-Identifier: MIT

use super::api::{DashboardResponse, DockerDetail, MavenDetail, PackageDetail};
use super::components::*;
use super::i18n::{get_translations, Lang};
use crate::repo_index::RepoInfo;
use crate::tokens::TokenListEntry;
use std::fmt::Write;

/// Renders the main dashboard page with dark theme
pub fn render_dashboard(data: &DashboardResponse, lang: Lang, auth_enabled: bool) -> String {
    let t = get_translations(lang);
    // Render global stats
    let global_stats = render_global_stats(
        data.global_stats.downloads,
        data.global_stats.uploads,
        data.global_stats.artifacts,
        data.global_stats.cache_hit_percent,
        data.global_stats.storage_bytes,
        lang,
    );

    // Render registry cards
    let registry_cards: String = data
        .registry_stats
        .iter()
        .map(|r| {
            let icon = get_registry_icon(&r.name);
            let display_name = get_registry_title(&r.name);
            render_registry_card(
                display_name,
                icon,
                r.artifact_count,
                r.downloads,
                r.uploads,
                r.size_bytes,
                &format!("/ui/{}", r.name),
                t,
            )
        })
        .collect();

    // Render mount points
    let mount_data: Vec<(String, String, Option<String>)> = data
        .mount_points
        .iter()
        .map(|m| {
            (
                m.registry.clone(),
                m.mount_path.clone(),
                m.proxy_upstream.clone(),
            )
        })
        .collect();
    let mount_points = render_mount_points_table(&mount_data, t);

    // Render activity log
    let activity_rows: String = if data.activity.is_empty() {
        format!(
            r##"<tr><td colspan="5" class="py-8 text-center text-slate-500">{}</td></tr>"##,
            t.no_activity
        )
    } else {
        // Group consecutive identical entries (same action+artifact+registry+source)
        struct GroupedActivity {
            time: String,
            action: String,
            artifact: String,
            registry: String,
            source: String,
            count: usize,
        }

        let mut grouped: Vec<GroupedActivity> = Vec::new();
        for entry in &data.activity {
            let action = entry.action.to_string();
            let is_repeat = grouped.last().is_some_and(|last| {
                last.action == action
                    && last.artifact == entry.artifact
                    && last.registry == entry.registry
                    && last.source == entry.source
            });

            if is_repeat {
                if let Some(last) = grouped.last_mut() {
                    last.count += 1;
                }
            } else {
                grouped.push(GroupedActivity {
                    time: format_relative_time(&entry.timestamp),
                    action,
                    artifact: entry.artifact.clone(),
                    registry: entry.registry.clone(),
                    source: entry.source.clone(),
                    count: 1,
                });
            }
        }

        grouped
            .iter()
            .map(|g| {
                let display_artifact = if g.count > 1 {
                    format!("{} (x{})", g.artifact, g.count)
                } else {
                    g.artifact.clone()
                };
                render_activity_row(
                    &g.time,
                    &g.action,
                    &display_artifact,
                    &g.registry,
                    &g.source,
                )
            })
            .collect()
    };
    let activity_log = render_activity_log(&activity_rows, t);

    // Format uptime
    let hours = data.uptime_seconds / 3600;
    let mins = (data.uptime_seconds % 3600) / 60;
    let uptime_str = format!("{}h {}m", hours, mins);

    // Render bragging footer (demo builds only)
    #[cfg(feature = "demo")]
    let bragging_footer = {
        let stats = BraggingStats::collect(data.registry_stats.len(), data.startup_duration_ms);
        render_bragging_footer(lang, &stats)
    };
    #[cfg(not(feature = "demo"))]
    let bragging_footer = String::new();

    let content = format!(
        r##"
        <div class="mb-6">
            <div class="flex items-center justify-between">
                <div>
                    <h1 class="text-2xl font-bold text-slate-200 mb-1">{}</h1>
                    <p class="text-slate-400">{}</p>
                </div>
                <div class="text-right">
                    <div class="text-sm text-slate-500">{}</div>
                    <div id="uptime" class="text-lg font-semibold text-slate-300">{}</div>
                </div>
            </div>
        </div>

        {}

        <div class="grid grid-cols-2 md:grid-cols-4 lg:grid-cols-7 gap-2 md:gap-3 mb-6">
            {}
        </div>

        <div class="grid grid-cols-1 lg:grid-cols-2 gap-6 mb-6">
            {}
            {}
        </div>

        {}
    "##,
        t.dashboard_title,
        t.dashboard_subtitle,
        t.uptime,
        uptime_str,
        global_stats,
        registry_cards,
        mount_points,
        activity_log,
        bragging_footer,
    );

    let polling_script = render_polling_script();
    layout_dark(
        t.dashboard_title,
        &content,
        Some("dashboard"),
        &polling_script,
        lang,
        auth_enabled,
    )
}

/// Format timestamp as relative time (e.g., "2 min ago")
fn format_relative_time(timestamp: &chrono::DateTime<chrono::Utc>) -> String {
    let now = chrono::Utc::now();
    let diff = now.signed_duration_since(*timestamp);

    if diff.num_seconds() < 60 {
        "just now".to_string()
    } else if diff.num_minutes() < 60 {
        let mins = diff.num_minutes();
        format!("{} min{} ago", mins, if mins == 1 { "" } else { "s" })
    } else if diff.num_hours() < 24 {
        let hours = diff.num_hours();
        format!("{} hour{} ago", hours, if hours == 1 { "" } else { "s" })
    } else {
        let days = diff.num_days();
        format!("{} day{} ago", days, if days == 1 { "" } else { "s" })
    }
}

/// Renders a registry list page with pagination
#[allow(clippy::too_many_arguments)]
pub fn render_registry_list_paginated(
    registry_type: &str,
    title: &str,
    repos: &[RepoInfo],
    page: usize,
    limit: usize,
    total: usize,
    lang: Lang,
    auth_enabled: bool,
) -> String {
    let t = get_translations(lang);
    let icon = get_registry_icon(registry_type);

    let table_rows = if repos.is_empty() && page == 1 {
        format!(
            r##"<tr><td colspan="4" class="px-6 py-12 text-center text-slate-500">
            <div class="text-4xl mb-2">📭</div>
            <div>{}</div>
            <div class="text-sm mt-1">{}</div>
        </td></tr>"##,
            t.no_repos_found, t.push_first_artifact
        )
    } else if repos.is_empty() {
        format!(
            r##"<tr><td colspan="4" class="px-6 py-12 text-center text-slate-500">
            <div class="text-4xl mb-2">📭</div>
            <div>{}</div>
        </td></tr>"##,
            t.no_more_items
        )
    } else {
        repos
            .iter()
            .map(|repo| {
                let detail_url =
                    format!("/ui/{}/{}", registry_type, encode_uri_component(&repo.name));
                // For raw registry: show folder/file icons
                let icon = if repo.is_file {
                    r#"<svg class="w-4 h-4 flex-shrink-0 text-slate-400" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M7 21h10a2 2 0 002-2V9.414a1 1 0 00-.293-.707l-5.414-5.414A1 1 0 0012.586 3H7a2 2 0 00-2 2v14a2 2 0 002 2z"/></svg>"#
                } else {
                    r#"<svg class="w-4 h-4 flex-shrink-0 text-slate-400" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M3 7v10a2 2 0 002 2h14a2 2 0 002-2V9a2 2 0 00-2-2h-6l-2-2H5a2 2 0 00-2 2z"/></svg>"#
                };
                let versions_display = if repo.is_file {
                    String::new()
                } else {
                    format!("{}", repo.versions)
                };
                format!(
                    r##"
                <tr class="hover:bg-slate-700 cursor-pointer" onclick="window.location='{}'">
                    <td class="px-3 md:px-6 py-3 md:py-4">
                        <div class="flex items-center gap-3">{}<a href="{}" class="text-blue-400 hover:text-blue-300 font-medium">{}</a></div>
                    </td>
                    <td class="px-3 md:px-6 py-3 md:py-4 text-slate-400">{}</td>
                    <td class="px-3 md:px-6 py-3 md:py-4 text-slate-400 hidden md:table-cell">{}</td>
                    <td class="px-3 md:px-6 py-3 md:py-4 text-slate-500 text-sm hidden md:table-cell">{}</td>
                </tr>
            "##,
                    detail_url,
                    icon,
                    detail_url,
                    html_escape(&repo.name),
                    versions_display,
                    format_size(repo.size),
                    &repo.updated
                )
            })
            .collect::<Vec<_>>()
            .join("")
    };

    let version_label = match registry_type {
        "docker" => t.tags,
        "raw" => t.items,
        _ => t.versions,
    };

    // Pagination
    let total_pages = total.div_ceil(limit);
    let start_item = if total == 0 {
        0
    } else {
        (page - 1) * limit + 1
    };
    let end_item = (start_item + repos.len()).saturating_sub(1);

    let pagination = if total_pages > 1 {
        let mut pages_html = String::new();

        // Previous button
        if page > 1 {
            let _ = write!(
                pages_html,
                r##"<a href="/ui/{}?page={}&limit={}" class="px-3 py-1 rounded bg-slate-700 hover:bg-slate-600 text-slate-300">←</a>"##,
                registry_type,
                page - 1,
                limit
            );
        } else {
            pages_html.push_str(r##"<span class="px-3 py-1 rounded bg-slate-800 text-slate-600 cursor-not-allowed">←</span>"##);
        }

        // Page numbers (show max 7 pages around current)
        let start_page = if page <= 4 { 1 } else { page - 3 };
        let end_page = (start_page + 6).min(total_pages);

        if start_page > 1 {
            let _ = write!(
                pages_html,
                r##"<a href="/ui/{}?page=1&limit={}" class="px-3 py-1 rounded hover:bg-slate-700 text-slate-400">1</a>"##,
                registry_type, limit
            );
            if start_page > 2 {
                pages_html.push_str(r##"<span class="px-2 text-slate-600">...</span>"##);
            }
        }

        for p in start_page..=end_page {
            if p == page {
                let _ = write!(
                    pages_html,
                    r##"<span class="px-3 py-1 rounded bg-blue-600 text-white font-medium">{}</span>"##,
                    p
                );
            } else {
                let _ = write!(
                    pages_html,
                    r##"<a href="/ui/{}?page={}&limit={}" class="px-3 py-1 rounded hover:bg-slate-700 text-slate-400">{}</a>"##,
                    registry_type, p, limit, p
                );
            }
        }

        if end_page < total_pages {
            if end_page < total_pages - 1 {
                pages_html.push_str(r##"<span class="px-2 text-slate-600">...</span>"##);
            }
            let _ = write!(
                pages_html,
                r##"<a href="/ui/{}?page={}&limit={}" class="px-3 py-1 rounded hover:bg-slate-700 text-slate-400">{}</a>"##,
                registry_type, total_pages, limit, total_pages
            );
        }

        // Next button
        if page < total_pages {
            let _ = write!(
                pages_html,
                r##"<a href="/ui/{}?page={}&limit={}" class="px-3 py-1 rounded bg-slate-700 hover:bg-slate-600 text-slate-300">→</a>"##,
                registry_type,
                page + 1,
                limit
            );
        } else {
            pages_html.push_str(r##"<span class="px-3 py-1 rounded bg-slate-800 text-slate-600 cursor-not-allowed">→</span>"##);
        }

        format!(
            r##"
            <div class="mt-4 flex items-center justify-between">
                <div class="text-sm text-slate-500">
                    {}
                </div>
                <div class="flex items-center gap-1">
                    {}
                </div>
            </div>
            "##,
            t.showing_range
                .replace("{start}", &start_item.to_string())
                .replace("{end}", &end_item.to_string())
                .replace("{total}", &total.to_string()),
            pages_html
        )
    } else if total > 0 {
        format!(
            r##"<div class="mt-4 text-sm text-slate-500">{}</div>"##,
            t.showing_all.replace("{count}", &total.to_string())
        )
    } else {
        String::new()
    };

    let content = format!(
        r##"
        <div class="mb-6 flex flex-col md:flex-row md:items-center md:justify-between gap-4">
            <div class="flex items-center">
                <svg class="w-6 h-6 md:w-8 md:h-8 mr-3 text-slate-400 flex-shrink-0" fill="currentColor" viewBox="0 0 24 24">{}</svg>
                <div>
                    <h1 class="text-xl md:text-2xl font-bold text-slate-200">{}</h1>
                    <p class="text-slate-500">{} {}</p>
                </div>
            </div>
            <div class="flex items-center gap-4">
                <div class="relative w-full md:w-auto">
                    <input type="text"
                           placeholder="{}"
                           class="w-full md:w-auto pl-10 pr-4 py-2 bg-slate-800 border border-slate-600 text-slate-200 rounded-lg focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-transparent placeholder-slate-500"
                           hx-get="/api/ui/{}/search"
                           hx-trigger="keyup changed delay:300ms"
                           hx-target="#repo-table-body"
                           name="q">
                    <svg class="absolute left-3 top-2.5 h-5 w-5 text-slate-500" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                        <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M21 21l-6-6m2-5a7 7 0 11-14 0 7 7 0 0114 0z"/>
                    </svg>
                </div>
            </div>
        </div>

        <div class="bg-[#1e293b] rounded-lg shadow-sm border border-slate-700 overflow-x-auto">
            <table class="w-full">
                <thead class="bg-slate-800 border-b border-slate-700">
                    <tr>
                        <th class="px-3 md:px-6 py-3 text-left text-xs font-semibold text-slate-400 uppercase tracking-wider">{}</th>
                        <th class="px-3 md:px-6 py-3 text-left text-xs font-semibold text-slate-400 uppercase tracking-wider">{}</th>
                        <th class="px-3 md:px-6 py-3 text-left text-xs font-semibold text-slate-400 uppercase tracking-wider hidden md:table-cell">{}</th>
                        <th class="px-3 md:px-6 py-3 text-left text-xs font-semibold text-slate-400 uppercase tracking-wider hidden md:table-cell">{}</th>
                    </tr>
                </thead>
                <tbody id="repo-table-body" class="divide-y divide-slate-700">
                    {}
                </tbody>
            </table>
        </div>
        {}
    "##,
        icon,
        title,
        total,
        t.repositories,
        t.search_placeholder,
        registry_type,
        t.name,
        version_label,
        t.size,
        t.updated,
        table_rows,
        pagination
    );

    layout_dark(title, &content, Some(registry_type), "", lang, auth_enabled)
}

/// Renders Docker image detail page
pub fn render_docker_detail(
    name: &str,
    detail: &DockerDetail,
    lang: Lang,
    base_url: &str,
    auth_enabled: bool,
) -> String {
    let _t = get_translations(lang);
    let tags_rows = if detail.tags.is_empty() {
        r##"<tr><td colspan="3" class="px-6 py-8 text-center text-slate-500">No tags found</td></tr>"##.to_string()
    } else {
        detail
            .tags
            .iter()
            .map(|tag| {
                format!(
                    r##"
                <tr class="hover:bg-slate-700">
                    <td class="px-3 md:px-6 py-3 md:py-4">
                        <span class="font-mono text-sm bg-slate-700 text-slate-200 px-2 py-1 rounded">{}</span>
                    </td>
                    <td class="px-3 md:px-6 py-3 md:py-4 text-slate-400">{}</td>
                    <td class="px-3 md:px-6 py-3 md:py-4 text-slate-500 text-sm hidden md:table-cell">{}</td>
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

    let registry_host = base_url
        .trim_start_matches("https://")
        .trim_start_matches("http://");
    let pull_cmd = format!("docker pull {}/{}", registry_host, name);

    let content = format!(
        r##"
        <div class="mb-6">
            <div class="flex items-center mb-2">
                <a href="/ui/docker" class="text-blue-400 hover:text-blue-300">Docker Registry</a>
                <span class="mx-2 text-slate-500">/</span>
                <span class="text-slate-200 font-medium">{}</span>
            </div>
            <div class="flex items-center">
                <svg class="w-6 h-6 md:w-8 md:h-8 mr-3 text-slate-400 flex-shrink-0" fill="currentColor" viewBox="0 0 24 24">{}</svg>
                <h1 class="text-xl md:text-2xl font-bold text-slate-200">{}</h1>
            </div>
        </div>

        <div class="bg-[#1e293b] rounded-lg shadow-sm border border-slate-700 p-3 md:p-6 mb-6">
            <h2 class="text-lg font-semibold text-slate-200 mb-3">Pull Command</h2>
            <div class="flex items-center bg-slate-900 text-green-400 rounded-lg p-3 md:p-4 font-mono text-xs md:text-sm overflow-x-auto">
                <code class="flex-1 whitespace-nowrap">{}</code>
                <button onclick="navigator.clipboard.writeText('{}')" class="ml-4 text-slate-400 hover:text-white transition-colors flex-shrink-0" title="Copy to clipboard">
                    <svg class="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                        <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M8 16H6a2 2 0 01-2-2V6a2 2 0 012-2h8a2 2 0 012 2v2m-6 12h8a2 2 0 002-2v-8a2 2 0 00-2-2h-8a2 2 0 00-2 2v8a2 2 0 002 2z"/>
                    </svg>
                </button>
            </div>
        </div>

        <div class="bg-[#1e293b] rounded-lg shadow-sm border border-slate-700 overflow-x-auto">
            <div class="px-3 md:px-6 py-4 border-b border-slate-700">
                <h2 class="text-lg font-semibold text-slate-200">Tags ({} total)</h2>
            </div>
            <table class="w-full">
                <thead class="bg-slate-800 border-b border-slate-700">
                    <tr>
                        <th class="px-3 md:px-6 py-3 text-left text-xs font-semibold text-slate-400 uppercase tracking-wider">Tag</th>
                        <th class="px-3 md:px-6 py-3 text-left text-xs font-semibold text-slate-400 uppercase tracking-wider">Size</th>
                        <th class="px-3 md:px-6 py-3 text-left text-xs font-semibold text-slate-400 uppercase tracking-wider hidden md:table-cell">Created</th>
                    </tr>
                </thead>
                <tbody class="divide-y divide-slate-700">
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

    layout_dark(
        &format!("{} - Docker", name),
        &content,
        Some("docker"),
        "",
        lang,
        auth_enabled,
    )
}

/// Renders a raw directory browser with breadcrumbs and folder/file listing
pub fn render_raw_dir(
    path: &str,
    entries: &[RepoInfo],
    total: usize,
    lang: Lang,
    auth_enabled: bool,
) -> String {
    let t = get_translations(lang);

    // Build breadcrumbs: Raw / docs / api / v1
    let segments: Vec<&str> = path.split('/').collect();
    let mut breadcrumbs =
        r#"<a href="/ui/raw" class="text-blue-400 hover:text-blue-300">Raw</a>"#.to_string();
    for (i, seg) in segments.iter().enumerate() {
        let crumb_path = segments[..=i]
            .iter()
            .copied()
            .map(encode_uri_component)
            .collect::<Vec<_>>()
            .join("/");
        if i == segments.len() - 1 {
            let _ = write!(
                breadcrumbs,
                r#"<span class="mx-2 text-slate-500">/</span><span class="text-slate-200 font-medium">{}</span>"#,
                html_escape(seg)
            );
        } else {
            let _ = write!(
                breadcrumbs,
                r#"<span class="mx-2 text-slate-500">/</span><a href="/ui/raw/{}" class="text-blue-400 hover:text-blue-300">{}</a>"#,
                crumb_path,
                html_escape(seg)
            );
        }
    }

    let rows: String = entries
        .iter()
        .map(|entry| {
            let icon = if entry.is_file {
                r#"<svg class="w-4 h-4 flex-shrink-0 text-slate-400" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M7 21h10a2 2 0 002-2V9.414a1 1 0 00-.293-.707l-5.414-5.414A1 1 0 0012.586 3H7a2 2 0 00-2 2v14a2 2 0 002 2z"/></svg>"#
            } else {
                r#"<svg class="w-4 h-4 flex-shrink-0 text-slate-400" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M3 7v10a2 2 0 002 2h14a2 2 0 002-2V9a2 2 0 00-2-2h-6l-2-2H5a2 2 0 00-2 2z"/></svg>"#
            };
            let encoded_path = path
                .split('/')
                .map(encode_uri_component)
                .collect::<Vec<_>>()
                .join("/");
            let href = format!("/ui/raw/{}/{}", encoded_path, encode_uri_component(&entry.name));
            let versions_display = if entry.is_file {
                String::new()
            } else {
                format!("{}", entry.versions)
            };
            format!(
                r##"
                <tr class="hover:bg-slate-700 cursor-pointer" onclick="window.location='{}'">
                    <td class="px-3 md:px-6 py-3 md:py-4">
                        <div class="flex items-center gap-3">{}<a href="{}" class="text-blue-400 hover:text-blue-300 font-medium">{}</a></div>
                    </td>
                    <td class="px-3 md:px-6 py-3 md:py-4 text-slate-400">{}</td>
                    <td class="px-3 md:px-6 py-3 md:py-4 text-slate-400 hidden md:table-cell">{}</td>
                    <td class="px-3 md:px-6 py-3 md:py-4 text-slate-500 text-sm hidden md:table-cell">{}</td>
                </tr>
            "##,
                href, icon, href, html_escape(&entry.name),
                versions_display, format_size(entry.size), &entry.updated
            )
        })
        .collect();

    let showing = t.showing_all.replace("{count}", &total.to_string());

    let content = format!(
        r##"
        <div class="mb-6">
            <div class="flex items-center mb-4 text-sm">{breadcrumbs}</div>
            <div class="flex items-center">
                <svg class="w-6 h-6 mr-3 text-slate-400 flex-shrink-0" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M3 7v10a2 2 0 002 2h14a2 2 0 002-2V9a2 2 0 00-2-2h-6l-2-2H5a2 2 0 00-2 2z"/></svg>
                <h1 class="text-2xl font-bold text-slate-200">{title}</h1>
            </div>
        </div>

        <div class="bg-[#1e293b] rounded-lg shadow-sm border border-slate-700 overflow-x-auto">
            <table class="w-full">
                <thead class="bg-slate-800 border-b border-slate-700">
                    <tr>
                        <th class="px-3 md:px-6 py-3 text-left text-xs font-semibold text-slate-400 uppercase tracking-wider">{col_name}</th>
                        <th class="px-3 md:px-6 py-3 text-left text-xs font-semibold text-slate-400 uppercase tracking-wider">{col_versions}</th>
                        <th class="px-3 md:px-6 py-3 text-left text-xs font-semibold text-slate-400 uppercase tracking-wider hidden md:table-cell">{col_size}</th>
                        <th class="px-3 md:px-6 py-3 text-left text-xs font-semibold text-slate-400 uppercase tracking-wider hidden md:table-cell">{col_updated}</th>
                    </tr>
                </thead>
                <tbody class="divide-y divide-slate-700">
                    {rows}
                </tbody>
            </table>
            <div class="mt-4 mb-4 ml-4 text-sm text-slate-500">{showing}</div>
        </div>
    "##,
        breadcrumbs = breadcrumbs,
        title = html_escape(segments.last().unwrap_or(&path)),
        col_name = t.name,
        col_versions = t.items,
        col_size = t.size,
        col_updated = t.updated,
        rows = rows,
        showing = showing,
    );

    layout_dark(
        &format!("{} — Raw", path),
        &content,
        Some("raw"),
        "",
        lang,
        auth_enabled,
    )
}

/// Renders a Maven namespace directory browser with breadcrumbs
pub fn render_maven_dir(
    path: &str,
    entries: &[RepoInfo],
    total: usize,
    lang: Lang,
    auth_enabled: bool,
) -> String {
    let t = get_translations(lang);

    // Build breadcrumbs: Maven Repository / com / example / webapp
    let mut breadcrumbs =
        r#"<a href="/ui/maven" class="text-blue-400 hover:text-blue-300">Maven</a>"#.to_string();
    if !path.is_empty() {
        let segments: Vec<&str> = path.split('/').collect();
        for (i, seg) in segments.iter().enumerate() {
            let crumb_path = segments[..=i].join("/");
            if i == segments.len() - 1 {
                let _ = write!(
                    breadcrumbs,
                    r#"<span class="mx-2 text-slate-500">/</span><span class="text-slate-200 font-medium">{}</span>"#,
                    html_escape(seg)
                );
            } else {
                let _ = write!(
                    breadcrumbs,
                    r#"<span class="mx-2 text-slate-500">/</span><a href="/ui/maven/{}" class="text-blue-400 hover:text-blue-300">{}</a>"#,
                    crumb_path,
                    html_escape(seg)
                );
            }
        }
    }

    let folder_icon = r#"<svg class="w-4 h-4 flex-shrink-0 text-slate-400" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M3 7v10a2 2 0 002 2h14a2 2 0 002-2V9a2 2 0 00-2-2h-6l-2-2H5a2 2 0 00-2 2z"/></svg>"#;

    let rows: String = entries
        .iter()
        .map(|entry| {
            let href = if path.is_empty() {
                format!("/ui/maven/{}", encode_uri_component(&entry.name))
            } else {
                format!("/ui/maven/{}/{}", path, encode_uri_component(&entry.name))
            };
            format!(
                r##"
                <tr class="hover:bg-slate-700 cursor-pointer" onclick="window.location='{}'">
                    <td class="px-3 md:px-6 py-3 md:py-4">
                        <div class="flex items-center gap-3">{}<a href="{}" class="text-blue-400 hover:text-blue-300 font-medium">{}</a></div>
                    </td>
                    <td class="px-3 md:px-6 py-3 md:py-4 text-slate-400">{}</td>
                    <td class="px-3 md:px-6 py-3 md:py-4 text-slate-400 hidden md:table-cell">{}</td>
                    <td class="px-3 md:px-6 py-3 md:py-4 text-slate-500 text-sm hidden md:table-cell">{}</td>
                </tr>
            "##,
                href,
                folder_icon,
                href,
                html_escape(&entry.name),
                entry.versions,
                format_size(entry.size),
                &entry.updated,
            )
        })
        .collect();

    let title_display = if path.is_empty() {
        "Maven Repository".to_string()
    } else {
        html_escape(path.rsplit('/').next().unwrap_or(path))
    };
    let showing = t.showing_all.replace("{count}", &total.to_string());

    let content = format!(
        r##"
        <div class="mb-6">
            <div class="flex items-center mb-4 text-sm">{breadcrumbs}</div>
            <div class="flex items-center">
                <svg class="w-6 h-6 md:w-8 md:h-8 mr-3 text-slate-400 flex-shrink-0" fill="currentColor" viewBox="0 0 24 24">{icon}</svg>
                <h1 class="text-xl md:text-2xl font-bold text-slate-200">{title}</h1>
            </div>
        </div>

        <div class="bg-[#1e293b] rounded-lg shadow-sm border border-slate-700 overflow-x-auto">
            <table class="w-full">
                <thead class="bg-slate-800 border-b border-slate-700">
                    <tr>
                        <th class="px-3 md:px-6 py-3 text-left text-xs font-semibold text-slate-400 uppercase tracking-wider">{col_name}</th>
                        <th class="px-3 md:px-6 py-3 text-left text-xs font-semibold text-slate-400 uppercase tracking-wider">{col_items}</th>
                        <th class="px-3 md:px-6 py-3 text-left text-xs font-semibold text-slate-400 uppercase tracking-wider hidden md:table-cell">{col_size}</th>
                        <th class="px-3 md:px-6 py-3 text-left text-xs font-semibold text-slate-400 uppercase tracking-wider hidden md:table-cell">{col_updated}</th>
                    </tr>
                </thead>
                <tbody class="divide-y divide-slate-700">
                    {rows}
                </tbody>
            </table>
            <div class="mt-4 mb-4 ml-4 text-sm text-slate-500">{showing}</div>
        </div>
    "##,
        breadcrumbs = breadcrumbs,
        icon = icons::MAVEN,
        title = title_display,
        col_name = t.name,
        col_items = t.items,
        col_size = t.size,
        col_updated = t.updated,
        rows = rows,
        showing = showing,
    );

    layout_dark(
        &format!("Maven — {}", if path.is_empty() { "Browse" } else { path }),
        &content,
        Some("maven"),
        "",
        lang,
        auth_enabled,
    )
}

/// Renders package detail page (npm, cargo, pypi)
pub fn render_package_detail(
    registry_type: &str,
    name: &str,
    detail: &PackageDetail,
    lang: Lang,
    base_url: &str,
    auth_enabled: bool,
) -> String {
    let _t = get_translations(lang);
    let icon = get_registry_icon(registry_type);
    let registry_title = get_registry_title(registry_type);

    let file_icon = if registry_type == "raw" {
        r#"<svg class="w-4 h-4 flex-shrink-0 text-slate-400" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M7 21h10a2 2 0 002-2V9.414a1 1 0 00-.293-.707l-5.414-5.414A1 1 0 0012.586 3H7a2 2 0 00-2 2v14a2 2 0 002 2z"/></svg>"#
    } else {
        ""
    };

    let versions_rows = if detail.versions.is_empty() {
        format!(
            r##"<tr><td colspan="3" class="px-6 py-8 text-center text-slate-500">{}</td></tr>"##,
            _t.no_repos_found
        )
    } else {
        detail
            .versions
            .iter()
            .map(|v| {
                let size_display = if v.cached {
                    format_size(v.size)
                } else {
                    "\u{2014}".to_string() // em dash
                };
                let cached_badge = if v.cached {
                    r#"<span class="ml-2 px-1.5 py-0.5 text-xs font-medium text-green-400 bg-green-900/30 border border-green-800 rounded">cached</span>"#
                } else {
                    ""
                };
                format!(
                    r##"
                <tr class="hover:bg-slate-700 cursor-pointer version-row" data-version="{ver}">
                    <td class="px-3 md:px-6 py-3 md:py-4">
                        <div class="flex items-center gap-2">{icon}<span class="font-mono text-sm bg-slate-700 text-slate-200 px-2 py-1 rounded">{ver}</span>{badge}</div>
                    </td>
                    <td class="px-3 md:px-6 py-3 md:py-4 text-slate-400">{size}</td>
                    <td class="px-3 md:px-6 py-3 md:py-4 text-slate-500 text-sm hidden md:table-cell">{pub_date}</td>
                </tr>
            "##,
                    ver = html_escape(&v.version),
                    icon = file_icon,
                    badge = cached_badge,
                    size = size_display,
                    pub_date = &v.published
                )
            })
            .collect::<Vec<_>>()
            .join("")
    };

    let prerelease_toggle = if detail.prerelease_count > 0 {
        format!(
            r##"<a href="/ui/{}/{}?prerelease=true" class="text-sm text-blue-400 hover:text-blue-300">+ {} pre-release</a>"##,
            registry_type,
            encode_uri_component(name),
            detail.prerelease_count
        )
    } else {
        String::new()
    };

    // "Show all N stable versions" link when list is truncated
    let show_all_link = if detail.total_stable > detail.versions.len() {
        format!(
            r##"<a href="/ui/{}/{}?all=true" class="block text-center py-3 text-sm text-blue-400 hover:text-blue-300 border-t border-slate-700">Show all {} stable versions</a>"##,
            registry_type,
            encode_uri_component(name),
            detail.total_stable
        )
    } else {
        String::new()
    };

    let install_cmd = match registry_type {
        "npm" => format!("npm install {} --registry {}/npm", name, base_url),
        "cargo" => format!("cargo add {}", name),
        "pypi" => format!("pip install {} --index-url {}/simple", name, base_url),
        "go" => format!("GOPROXY={}/go go get {}", base_url, name),
        "raw" => {
            if detail.versions.len() == 1 && detail.versions[0].version == name {
                // Root-level file — direct download URL
                format!("curl -O {}/raw/{}", base_url, name)
            } else {
                format!("curl -O {}/raw/{}/<file>", base_url, name)
            }
        }
        "nuget" => format!(
            "dotnet add package {} --source {}/nuget/v3/index.json",
            name, base_url
        ),
        "gems" => format!("gem install {} --source {}/gems", name, base_url),
        "terraform" => format!(
            "# In required_providers block:\n  source = \"{}/terraform/{}\"",
            base_url
                .trim_start_matches("https://")
                .trim_start_matches("http://"),
            name
        ),
        "ansible" => format!("ansible-galaxy collection install {}", name),
        "pub" => format!(
            "# pubspec.yaml:\n  hosted: {}/pub\n  # then: dart pub get",
            base_url
        ),
        "conan" => format!("conan install --requires={}/ -r nora", name),
        _ => String::new(),
    };

    // Build breadcrumbs — for raw, make each path segment clickable
    let breadcrumb_html = if registry_type == "raw" && name.contains('/') {
        let segments: Vec<&str> = name.split('/').collect();
        let mut crumbs =
            r#"<a href="/ui/raw" class="text-blue-400 hover:text-blue-300">Raw</a>"#.to_string();
        for (i, seg) in segments.iter().enumerate() {
            let crumb_path = segments[..=i]
                .iter()
                .copied()
                .map(encode_uri_component)
                .collect::<Vec<_>>()
                .join("/");
            if i == segments.len() - 1 {
                let _ = write!(
                    crumbs,
                    r#"<span class="mx-2 text-slate-500">/</span><span class="text-slate-200 font-medium">{}</span>"#,
                    html_escape(seg)
                );
            } else {
                let _ = write!(
                    crumbs,
                    r#"<span class="mx-2 text-slate-500">/</span><a href="/ui/raw/{}" class="text-blue-400 hover:text-blue-300">{}</a>"#,
                    crumb_path,
                    html_escape(seg)
                );
            }
        }
        crumbs
    } else {
        format!(
            r#"<a href="/ui/{reg}" class="text-blue-400 hover:text-blue-300">{title}</a><span class="mx-2 text-slate-500">/</span><span class="text-slate-200 font-medium">{name}</span>"#,
            reg = registry_type,
            title = registry_title,
            name = html_escape(name),
        )
    };

    let detail_title = if registry_type == "raw" && name.contains('/') {
        html_escape(name.rsplit('/').next().unwrap_or(name))
    } else {
        html_escape(name)
    };

    // Total versions displayed in header
    let display_total = if detail.total_stable > 0 {
        detail.total_stable
    } else {
        detail.versions.len()
    };

    // JavaScript for per-version install command (NuGet-specific)
    let version_js = if registry_type == "nuget" {
        format!(
            r##"<script>
document.querySelectorAll('.version-row').forEach(function(row) {{
    row.addEventListener('click', function() {{
        var ver = this.getAttribute('data-version');
        var cmd = 'dotnet add package {name} --version ' + ver + ' --source {base}/nuget/v3/index.json';
        var el = document.getElementById('install-cmd');
        if (el) {{ el.textContent = cmd; }}
        var btn = document.getElementById('copy-btn');
        if (btn) {{ btn.setAttribute('data-cmd', cmd); }}
        document.querySelectorAll('.version-row').forEach(function(r) {{ r.classList.remove('bg-slate-700/50'); }});
        this.classList.add('bg-slate-700/50');
    }});
}});
var copyBtn = document.getElementById('copy-btn');
if (copyBtn) {{ copyBtn.addEventListener('click', function() {{
    navigator.clipboard.writeText(this.getAttribute('data-cmd') || this.closest('.bg-\\[\\#1e293b\\]').querySelector('code').textContent);
}}); }}
</script>"##,
            name = html_escape(name),
            base = html_escape(base_url),
        )
    } else {
        String::new()
    };

    let content = format!(
        r##"
        <div class="mb-6">
            <div class="flex items-center mb-2 text-sm">
                {breadcrumbs}
            </div>
            <div class="flex items-center">
                <svg class="w-6 h-6 md:w-8 md:h-8 mr-3 text-slate-400 flex-shrink-0" fill="currentColor" viewBox="0 0 24 24">{icon}</svg>
                <h1 class="text-xl md:text-2xl font-bold text-slate-200">{title}</h1>
            </div>
        </div>

        <div class="bg-[#1e293b] rounded-lg shadow-sm border border-slate-700 p-3 md:p-6 mb-6">
            <h2 class="text-lg font-semibold text-slate-200 mb-3">{install_label}</h2>
            <div class="flex items-center bg-slate-900 text-green-400 rounded-lg p-3 md:p-4 font-mono text-xs md:text-sm overflow-x-auto">
                <code id="install-cmd" class="flex-1 whitespace-nowrap">{cmd}</code>
                <button id="copy-btn" data-cmd="{cmd}" onclick="navigator.clipboard.writeText(this.getAttribute('data-cmd'))" class="ml-4 text-slate-400 hover:text-white transition-colors flex-shrink-0" title="Copy to clipboard">
                    <svg class="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                        <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M8 16H6a2 2 0 01-2-2V6a2 2 0 012-2h8a2 2 0 012 2v2m-6 12h8a2 2 0 002-2v-8a2 2 0 00-2-2h-8a2 2 0 00-2 2v8a2 2 0 002 2z"/>
                    </svg>
                </button>
            </div>
        </div>

        <div class="bg-[#1e293b] rounded-lg shadow-sm border border-slate-700 overflow-x-auto">
            <div class="px-3 md:px-6 py-4 border-b border-slate-700 flex items-center justify-between">
                <h2 class="text-lg font-semibold text-slate-200">{versions_label} ({total} {total_word})</h2>
                {prerelease}
            </div>
            <table class="w-full">
                <thead class="bg-slate-800 border-b border-slate-700">
                    <tr>
                        <th class="px-3 md:px-6 py-3 text-left text-xs font-semibold text-slate-400 uppercase tracking-wider">{col_version}</th>
                        <th class="px-3 md:px-6 py-3 text-left text-xs font-semibold text-slate-400 uppercase tracking-wider">{col_size}</th>
                        <th class="px-3 md:px-6 py-3 text-left text-xs font-semibold text-slate-400 uppercase tracking-wider hidden md:table-cell">{col_published}</th>
                    </tr>
                </thead>
                <tbody class="divide-y divide-slate-700">
                    {rows}
                </tbody>
            </table>
            {show_all}
        </div>
        {js}
    "##,
        breadcrumbs = breadcrumb_html,
        icon = icon,
        title = detail_title,
        install_label = _t.install_command,
        cmd = install_cmd,
        versions_label = if registry_type == "raw" {
            _t.files
        } else {
            _t.versions
        },
        total = display_total,
        total_word = _t.total,
        prerelease = prerelease_toggle,
        col_version = if registry_type == "raw" {
            _t.filename
        } else {
            _t.versions
        },
        col_size = _t.size,
        col_published = _t.published,
        rows = versions_rows,
        show_all = show_all_link,
        js = version_js,
    );

    layout_dark(
        &format!("{} - {}", name, registry_title),
        &content,
        Some(registry_type),
        "",
        lang,
        auth_enabled,
    )
}

/// Renders Maven artifact detail page
pub fn render_maven_detail(
    path: &str,
    detail: &MavenDetail,
    lang: Lang,
    auth_enabled: bool,
) -> String {
    let _t = get_translations(lang);
    let artifact_rows = if detail.artifacts.is_empty() {
        r##"<tr><td colspan="2" class="px-6 py-8 text-center text-slate-500">No artifacts found</td></tr>"##.to_string()
    } else {
        detail.artifacts.iter().map(|a| {
            let download_url = format!("/maven2/{}/{}", path, a.filename);
            format!(r##"
                <tr class="hover:bg-slate-700">
                    <td class="px-3 md:px-6 py-3 md:py-4">
                        <a href="{}" class="text-blue-400 hover:text-blue-300 font-mono text-sm">{}</a>
                    </td>
                    <td class="px-3 md:px-6 py-3 md:py-4 text-slate-400">{}</td>
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

    // Build breadcrumbs: Maven / com / example / webapp / 2.0.0
    let mut breadcrumbs =
        r#"<a href="/ui/maven" class="text-blue-400 hover:text-blue-300">Maven</a>"#.to_string();
    let segments: Vec<&str> = path.split('/').collect();
    for (i, seg) in segments.iter().enumerate() {
        let crumb_path = segments[..=i].join("/");
        if i == segments.len() - 1 {
            let _ = write!(
                breadcrumbs,
                r#"<span class="mx-2 text-slate-500">/</span><span class="text-slate-200 font-medium">{}</span>"#,
                html_escape(seg)
            );
        } else {
            let _ = write!(
                breadcrumbs,
                r#"<span class="mx-2 text-slate-500">/</span><a href="/ui/maven/{}" class="text-blue-400 hover:text-blue-300">{}</a>"#,
                crumb_path,
                html_escape(seg)
            );
        }
    }

    let content = format!(
        r##"
        <div class="mb-6">
            <div class="flex items-center mb-4 text-sm">{breadcrumbs}</div>
            <div class="flex items-center">
                <svg class="w-6 h-6 md:w-8 md:h-8 mr-3 text-slate-400 flex-shrink-0" fill="currentColor" viewBox="0 0 24 24">{icon}</svg>
                <h1 class="text-xl md:text-2xl font-bold text-slate-200">{title}</h1>
            </div>
        </div>

        <div class="bg-[#1e293b] rounded-lg shadow-sm border border-slate-700 p-3 md:p-6 mb-6">
            <h2 class="text-lg font-semibold text-slate-200 mb-3">Maven Dependency</h2>
            <pre class="bg-slate-900 text-green-400 rounded-lg p-3 md:p-4 font-mono text-xs md:text-sm overflow-x-auto">{dep_xml}</pre>
        </div>

        <div class="bg-[#1e293b] rounded-lg shadow-sm border border-slate-700 overflow-x-auto">
            <div class="px-3 md:px-6 py-4 border-b border-slate-700">
                <h2 class="text-lg font-semibold text-slate-200">Artifacts ({count} files)</h2>
            </div>
            <table class="w-full">
                <thead class="bg-slate-800 border-b border-slate-700">
                    <tr>
                        <th class="px-3 md:px-6 py-3 text-left text-xs font-semibold text-slate-400 uppercase tracking-wider">Filename</th>
                        <th class="px-3 md:px-6 py-3 text-left text-xs font-semibold text-slate-400 uppercase tracking-wider">Size</th>
                    </tr>
                </thead>
                <tbody class="divide-y divide-slate-700">
                    {rows}
                </tbody>
            </table>
        </div>
    "##,
        breadcrumbs = breadcrumbs,
        icon = icons::MAVEN,
        title = html_escape(path),
        dep_xml = html_escape(&dep_cmd),
        count = detail.artifacts.len(),
        rows = artifact_rows
    );

    layout_dark(
        &format!("{} - Maven", path),
        &content,
        Some("maven"),
        "",
        lang,
        auth_enabled,
    )
}

// ==================== Token Management Pages ====================

/// Renders the token management page
pub fn render_tokens_page(tokens: &[TokenListEntry], lang: Lang, auth_enabled: bool) -> String {
    let t = get_translations(lang);

    let token_list = render_token_list_fragment(tokens, lang);

    let content = format!(
        r##"
        <div class="mb-6">
            <h1 class="text-2xl font-bold text-slate-200 mb-1">{title}</h1>
            <p class="text-slate-400">{subtitle}</p>
        </div>

        <!-- Create Token Form -->
        <div class="bg-[#1e293b] rounded-lg border border-slate-700 p-6 mb-6">
            <h2 class="text-lg font-semibold text-slate-200 mb-4">{create_title}</h2>
            <form hx-post="/api/ui/tokens/create"
                  hx-target="#create-result"
                  hx-swap="innerHTML"
                  class="space-y-4">
                <div class="grid grid-cols-1 md:grid-cols-3 gap-4">
                    <div>
                        <label class="block text-sm font-medium text-slate-300 mb-1">{desc_label}</label>
                        <input type="text" name="description" placeholder="{desc_placeholder}"
                               class="w-full px-3 py-2 bg-slate-800 border border-slate-600 text-slate-200 rounded-lg focus:outline-none focus:ring-2 focus:ring-blue-500 placeholder-slate-500"
                               required>
                    </div>
                    <div>
                        <label class="block text-sm font-medium text-slate-300 mb-1">{role_label}</label>
                        <select name="role"
                                class="w-full px-3 py-2 bg-slate-800 border border-slate-600 text-slate-200 rounded-lg focus:outline-none focus:ring-2 focus:ring-blue-500">
                            <option value="read">Read</option>
                            <option value="write">Write</option>
                            <option value="admin">Admin</option>
                        </select>
                    </div>
                    <div>
                        <label class="block text-sm font-medium text-slate-300 mb-1">{ttl_label} ({ttl_days})</label>
                        <input type="number" name="ttl_days" value="90" min="1" max="3650"
                               class="w-full px-3 py-2 bg-slate-800 border border-slate-600 text-slate-200 rounded-lg focus:outline-none focus:ring-2 focus:ring-blue-500">
                    </div>
                </div>
                <button type="submit"
                        class="px-4 py-2 bg-blue-600 hover:bg-blue-700 text-white font-medium rounded-lg transition-colors">
                    {create_btn}
                </button>
            </form>
            <div id="create-result" class="mt-4"></div>
        </div>

        <!-- Token List -->
        <div class="bg-[#1e293b] rounded-lg border border-slate-700 overflow-hidden">
            <div class="px-6 py-4 border-b border-slate-700">
                <h2 class="text-lg font-semibold text-slate-200">{nav_tokens}</h2>
            </div>
            <div id="token-list"
                 hx-get="/api/ui/tokens/list"
                 hx-trigger="refreshTokens from:body"
                 hx-swap="innerHTML">
                {token_list}
            </div>
        </div>
    "##,
        title = t.token_management,
        subtitle = t.token_management_subtitle,
        create_title = t.token_create,
        desc_label = t.token_description,
        desc_placeholder = t.token_description_placeholder,
        role_label = t.token_role,
        ttl_label = t.token_ttl,
        ttl_days = t.token_ttl_days,
        create_btn = t.token_create,
        nav_tokens = t.nav_tokens,
        token_list = token_list,
    );

    layout_dark(
        t.token_management,
        &content,
        Some("tokens"),
        "",
        lang,
        auth_enabled,
    )
}

/// Renders the HTMX fragment shown after token creation (with raw token)
pub fn render_token_created_fragment(raw_token: &str, lang: Lang) -> String {
    let t = get_translations(lang);
    format!(
        r##"
        <div class="bg-green-900/30 border border-green-700 rounded-lg p-4">
            <div class="flex items-start">
                <svg class="w-5 h-5 text-green-400 mt-0.5 mr-3 flex-shrink-0" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z"/>
                </svg>
                <div class="flex-1">
                    <p class="text-green-400 font-medium mb-2">{success}</p>
                    <div class="flex items-center bg-slate-900 rounded-lg p-3 font-mono text-sm text-slate-200">
                        <code class="flex-1 break-all">{token}</code>
                        <button onclick="navigator.clipboard.writeText('{token}'); this.textContent='OK'; setTimeout(() => this.textContent='{copy}', 2000)"
                                class="ml-3 px-3 py-1 bg-slate-700 hover:bg-slate-600 text-slate-300 rounded text-xs font-medium transition-colors flex-shrink-0">
                            {copy}
                        </button>
                    </div>
                    <p class="text-yellow-400 text-sm mt-2">{warning}</p>
                </div>
            </div>
        </div>
        <script>document.body.dispatchEvent(new Event('refreshTokens'));</script>
    "##,
        success = html_escape(t.token_created_success),
        token = html_escape(raw_token),
        copy = t.token_copy,
        warning = html_escape(t.token_created_warning),
    )
}

/// Renders the token list table body (HTMX fragment for refresh)
pub fn render_token_list_fragment(tokens: &[TokenListEntry], lang: Lang) -> String {
    let t = get_translations(lang);

    if tokens.is_empty() {
        return format!(
            r##"<div class="px-6 py-12 text-center text-slate-500">{}</div>"##,
            t.token_no_tokens
        );
    }

    // Sort: active tokens first, expired last
    let mut sorted_tokens: Vec<&TokenListEntry> = tokens.iter().collect();
    let now_ts = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    sorted_tokens.sort_by_key(|t| if t.expires_at <= now_ts { 1u8 } else { 0u8 });

    let rows: String = sorted_tokens
        .iter()
        .map(|token| {
            let role_badge = render_role_badge(&token.role);
            let description = token
                .description
                .as_deref()
                .unwrap_or("-");
            let (expires_text, is_expired) = format_expiry(token.expires_at);
            let expires_html = if is_expired {
                format!(r##"<span class="px-2 py-0.5 text-xs font-medium text-red-400 bg-red-900/30 border border-red-800 rounded">{}</span>"##, expires_text)
            } else {
                format!(r##"<span class="text-slate-400">{}</span>"##, expires_text)
            };
            let last_used = token
                .last_used
                .map(format_timestamp)
                .unwrap_or_else(|| t.token_never_used.to_string());
            let row_class = if is_expired {
                "border-b border-slate-700/50 opacity-60"
            } else {
                "border-b border-slate-700/50"
            };

            format!(
                r##"
                <tr class="{row_class}">
                    <td class="px-6 py-4 text-slate-300">{desc}</td>
                    <td class="px-6 py-4 text-slate-400">{user}</td>
                    <td class="px-6 py-4">{role}</td>
                    <td class="px-6 py-4 text-sm">{expires}</td>
                    <td class="px-6 py-4 text-slate-500 text-sm">{last_used}</td>
                    <td class="px-6 py-4">
                        <button hx-post="/api/ui/tokens/{file_id}/revoke"
                                hx-confirm="{confirm}"
                                hx-target="#token-list"
                                hx-swap="innerHTML"
                                class="px-3 py-1 text-xs font-medium text-red-400 hover:text-red-300 bg-red-900/20 hover:bg-red-900/40 border border-red-800 rounded transition-colors">
                            {revoke}
                        </button>
                    </td>
                </tr>
            "##,
                row_class = row_class,
                desc = html_escape(description),
                user = html_escape(&token.user),
                role = role_badge,
                expires = expires_html,
                last_used = last_used,
                file_id = html_escape(&token.file_id),
                confirm = html_escape(t.token_revoke_confirm),
                revoke = t.token_revoke,
            )
        })
        .collect();

    format!(
        r##"
        <table class="w-full">
            <thead class="bg-slate-800 border-b border-slate-700">
                <tr>
                    <th class="px-6 py-3 text-left text-xs font-semibold text-slate-400 uppercase tracking-wider">{}</th>
                    <th class="px-6 py-3 text-left text-xs font-semibold text-slate-400 uppercase tracking-wider">{}</th>
                    <th class="px-6 py-3 text-left text-xs font-semibold text-slate-400 uppercase tracking-wider">{}</th>
                    <th class="px-6 py-3 text-left text-xs font-semibold text-slate-400 uppercase tracking-wider">{}</th>
                    <th class="px-6 py-3 text-left text-xs font-semibold text-slate-400 uppercase tracking-wider">{}</th>
                    <th class="px-6 py-3 text-left text-xs font-semibold text-slate-400 uppercase tracking-wider"></th>
                </tr>
            </thead>
            <tbody>
                {}
            </tbody>
        </table>
    "##,
        t.token_description, t.token_user, t.token_role, t.token_expires, t.token_last_used, rows,
    )
}

/// Renders a colored role badge
fn render_role_badge(role: &crate::tokens::Role) -> String {
    let (color, bg) = match role {
        crate::tokens::Role::Read => ("text-blue-400", "bg-blue-900/30 border-blue-800"),
        crate::tokens::Role::Write => ("text-green-400", "bg-green-900/30 border-green-800"),
        crate::tokens::Role::Admin => ("text-purple-400", "bg-purple-900/30 border-purple-800"),
    };
    format!(
        r##"<span class="px-2 py-0.5 text-xs font-medium {} {} border rounded">{}</span>"##,
        color, bg, role
    )
}

/// Returns SVG icon path for the registry type
fn get_registry_icon(registry_type: &str) -> &'static str {
    match registry_type {
        "docker" => icons::DOCKER,
        "maven" => icons::MAVEN,
        "npm" => icons::NPM,
        "cargo" => icons::CARGO,
        "pypi" => icons::PYPI,
        "go" => icons::GO,
        "raw" => icons::RAW,
        "gems" => icons::GEMS,
        "terraform" => icons::TERRAFORM,
        "ansible" => icons::ANSIBLE,
        "nuget" => icons::NUGET,
        "pub" => icons::PUB,
        "conan" => icons::CONAN,
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
        "go" => "Go Modules",
        "raw" => "Raw Storage",
        "gems" => "RubyGems",
        "terraform" => "Terraform Registry",
        "ansible" => "Ansible Galaxy",
        "nuget" => "NuGet Gallery",
        "pub" => "pub.dev",
        "conan" => "Conan (C/C++)",
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
                    let _ = write!(result, "%{:02X}", byte);
                }
            }
        }
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ui::api::PackageDetail;

    fn empty_detail() -> PackageDetail {
        PackageDetail {
            versions: vec![],
            prerelease_count: 0,
            total_stable: 0,
        }
    }

    #[test]
    fn test_package_detail_uses_public_url() {
        let base_url = "https://registry.example.com";
        let html = render_package_detail(
            "pypi",
            "requests",
            &empty_detail(),
            Lang::En,
            base_url,
            false,
        );
        assert!(
            html.contains("https://registry.example.com/simple"),
            "PyPI install command must use public_url"
        );
        assert!(
            !html.contains("127.0.0.1"),
            "Must not contain hardcoded localhost"
        );

        let html =
            render_package_detail("npm", "lodash", &empty_detail(), Lang::En, base_url, false);
        assert!(
            html.contains("https://registry.example.com/npm"),
            "npm install command must use public_url"
        );

        let html = render_package_detail(
            "go",
            "github.com/foo/bar",
            &empty_detail(),
            Lang::En,
            base_url,
            false,
        );
        assert!(
            html.contains("https://registry.example.com/go"),
            "Go proxy command must use public_url"
        );

        let html =
            render_package_detail("raw", "myfiles", &empty_detail(), Lang::En, base_url, false);
        assert!(
            html.contains("https://registry.example.com/raw"),
            "Raw download command must use public_url"
        );
    }

    #[test]
    fn test_package_detail_fallback_url() {
        let base_url = "http://0.0.0.0:4000";
        let html =
            render_package_detail("pypi", "flask", &empty_detail(), Lang::En, base_url, false);
        assert!(
            html.contains("http://0.0.0.0:4000/simple"),
            "Must use fallback host:port when public_url is not set"
        );
    }

    #[test]
    fn test_docker_detail_strips_scheme() {
        let detail = super::super::api::DockerDetail { tags: vec![] };

        let html = render_docker_detail(
            "myapp",
            &detail,
            Lang::En,
            "https://registry.example.com",
            false,
        );
        assert!(
            html.contains("docker pull registry.example.com/myapp"),
            "Docker pull must strip https:// scheme"
        );
        assert!(
            !html.contains("https://registry.example.com/myapp"),
            "Docker pull must not include scheme"
        );

        let html = render_docker_detail("myapp", &detail, Lang::En, "http://localhost:4000", false);
        assert!(
            html.contains("docker pull localhost:4000/myapp"),
            "Docker pull must strip http:// scheme"
        );
    }

    #[test]
    fn test_trailing_slash_no_double_slash() {
        let base_url = "https://registry.example.com";
        let html = render_package_detail("pypi", "pkg", &empty_detail(), Lang::En, base_url, false);
        assert!(
            !html.contains("com//simple"),
            "Must not produce double slashes"
        );
    }

    #[test]
    fn test_render_tokens_page_empty() {
        let html = render_tokens_page(&[], Lang::En, true);
        assert!(html.contains("Token Management"));
        assert!(html.contains("No tokens yet"));
        assert!(html.contains("/api/ui/tokens/create"));
    }

    #[test]
    fn test_render_role_badge() {
        let badge = render_role_badge(&crate::tokens::Role::Admin);
        assert!(badge.contains("purple"));
        assert!(badge.contains("admin"));
    }

    #[test]
    fn test_render_token_created_fragment() {
        let html = render_token_created_fragment("nra_test_token_123", Lang::En);
        assert!(html.contains("nra_test_token_123"));
        assert!(html.contains("refreshTokens"));
        assert!(html.contains("Copy"));
    }

    #[test]
    fn test_raw_root_file_install_command() {
        let base_url = "https://registry.example.com";

        // Root-level file: single version whose name equals the group
        let detail = PackageDetail {
            versions: vec![crate::ui::api::VersionInfo {
                version: "myfile.txt".to_string(),
                size: 42,
                published: "2026-04-29".to_string(),
                cached: true,
            }],
            prerelease_count: 0,
            total_stable: 0,
        };
        let html = render_package_detail("raw", "myfile.txt", &detail, Lang::En, base_url, false);
        assert!(
            html.contains("curl -O https://registry.example.com/raw/myfile.txt"),
            "Root-level raw file must have direct download URL"
        );
        assert!(
            !html.contains("/raw/myfile.txt/"),
            "Root-level raw file must NOT have trailing slash or /<file>"
        );

        // Subdirectory group: multiple files or version != name
        let subdir_detail = PackageDetail {
            versions: vec![
                crate::ui::api::VersionInfo {
                    version: "a.txt".to_string(),
                    size: 10,
                    published: "2026-04-29".to_string(),
                    cached: true,
                },
                crate::ui::api::VersionInfo {
                    version: "b.txt".to_string(),
                    size: 20,
                    published: "2026-04-29".to_string(),
                    cached: true,
                },
            ],
            prerelease_count: 0,
            total_stable: 0,
        };
        let html =
            render_package_detail("raw", "subdir", &subdir_detail, Lang::En, base_url, false);
        assert!(
            html.contains("curl -O https://registry.example.com/raw/subdir/<file>"),
            "Subdirectory raw group must show <file> placeholder"
        );
    }
}
