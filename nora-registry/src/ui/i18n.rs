// Copyright (c) 2026 The NORA Authors
// SPDX-License-Identifier: MIT

/// Internationalization support for the UI
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Lang {
    #[default]
    En,
    Ru,
    Zh,
}

impl Lang {
    pub fn from_str(s: &str) -> Self {
        let lower = s.to_lowercase();
        // Match on the primary language subtag, ignoring any region/script
        // suffix so BCP-47 / POSIX tags ("zh-CN", "zh-Hans", "ru_RU.UTF-8")
        // resolve the same as their bare code. Simplified Chinese is the only
        // Chinese variant available, so every "zh*" tag maps to it.
        let primary = lower
            .split(['-', '_'])
            .next()
            .expect("str::split always yields at least one segment");
        match primary {
            "ru" | "rus" | "russian" => Lang::Ru,
            "zh" | "zho" | "chs" | "chinese" => Lang::Zh,
            _ => Lang::En,
        }
    }

    pub fn code(&self) -> &'static str {
        match self {
            Lang::En => "en",
            Lang::Ru => "ru",
            Lang::Zh => "zh",
        }
    }
}

/// All translatable strings
#[allow(dead_code)]
pub struct Translations {
    // Navigation
    pub nav_dashboard: &'static str,
    pub nav_registries: &'static str,

    // Dashboard
    pub dashboard_title: &'static str,
    pub dashboard_subtitle: &'static str,
    pub uptime: &'static str,

    // Stats
    pub stat_downloads: &'static str,
    pub stat_uploads: &'static str,
    pub stat_artifacts: &'static str,
    pub stat_cache_hit: &'static str,
    pub stat_storage: &'static str,
    pub stats_since_restart: &'static str,

    // Registry cards
    pub active: &'static str,
    pub artifacts: &'static str,
    pub size: &'static str,
    pub downloads: &'static str,
    pub uploads: &'static str,

    // Mount points
    pub mount_points: &'static str,
    pub registry: &'static str,
    pub mount_path: &'static str,
    pub proxy_upstream: &'static str,

    // Activity
    pub recent_activity: &'static str,
    pub last_n_events: &'static str,
    pub time: &'static str,
    pub action: &'static str,
    pub artifact: &'static str,
    pub source: &'static str,
    pub no_activity: &'static str,

    // Relative time
    pub just_now: &'static str,
    pub min_ago: &'static str,
    pub mins_ago: &'static str,
    pub hour_ago: &'static str,
    pub hours_ago: &'static str,
    pub day_ago: &'static str,
    pub days_ago: &'static str,

    // Registry pages
    pub repositories: &'static str,
    pub search_placeholder: &'static str,
    pub no_repos_found: &'static str,
    pub push_first_artifact: &'static str,
    pub name: &'static str,
    pub tags: &'static str,
    pub versions: &'static str,
    pub updated: &'static str,

    // Detail pages
    pub pull_command: &'static str,
    pub install_command: &'static str,
    pub maven_dependency: &'static str,
    pub total: &'static str,
    pub created: &'static str,
    pub published: &'static str,
    pub filename: &'static str,
    pub files: &'static str,

    // Bragging footer
    pub built_for_speed: &'static str,
    pub docker_image: &'static str,
    pub cold_start: &'static str,
    pub memory: &'static str,
    pub registries_count: &'static str,
    pub multi_arch: &'static str,
    pub zero_config: &'static str,
    pub tagline: &'static str,

    // Token management
    pub nav_admin: &'static str,
    pub nav_tokens: &'static str,
    pub token_management: &'static str,
    pub token_management_subtitle: &'static str,
    pub token_create: &'static str,
    pub token_revoke: &'static str,
    pub token_revoke_confirm: &'static str,
    pub token_description: &'static str,
    pub token_description_placeholder: &'static str,
    pub token_role: &'static str,
    pub token_ttl: &'static str,
    pub token_ttl_days: &'static str,
    pub token_created_success: &'static str,
    pub token_created_warning: &'static str,
    pub token_copy: &'static str,
    pub token_no_tokens: &'static str,
    pub token_user: &'static str,
    pub token_expires: &'static str,
    pub token_last_used: &'static str,
    pub token_never_used: &'static str,

    // Pagination
    pub showing_range: &'static str,
    pub showing_all: &'static str,
    pub no_more_items: &'static str,
    pub one_file: &'static str,
    pub items: &'static str,
}

pub fn get_translations(lang: Lang) -> &'static Translations {
    match lang {
        Lang::En => &TRANSLATIONS_EN,
        Lang::Ru => &TRANSLATIONS_RU,
        Lang::Zh => &TRANSLATIONS_ZH,
    }
}

pub static TRANSLATIONS_EN: Translations = Translations {
    // Navigation
    nav_dashboard: "Dashboard",
    nav_registries: "Registries",

    // Dashboard
    dashboard_title: "Dashboard",
    dashboard_subtitle: "Overview of all registries",
    uptime: "Uptime",

    // Stats
    stat_downloads: "Downloads",
    stat_uploads: "Uploads",
    stat_artifacts: "Artifacts",
    stat_cache_hit: "Cache Hit",
    stat_storage: "Storage",
    stats_since_restart: "since restart",

    // Registry cards
    active: "ACTIVE",
    artifacts: "Artifacts",
    size: "Size",
    downloads: "Downloads",
    uploads: "Uploads",

    // Mount points
    mount_points: "Mount Points",
    registry: "Registry",
    mount_path: "Mount Path",
    proxy_upstream: "Proxy Upstream",

    // Activity
    recent_activity: "Recent Activity",
    last_n_events: "Last 20 events",
    time: "Time",
    action: "Action",
    artifact: "Artifact",
    source: "Source",
    no_activity: "No recent activity",

    // Relative time
    just_now: "just now",
    min_ago: "min ago",
    mins_ago: "mins ago",
    hour_ago: "hour ago",
    hours_ago: "hours ago",
    day_ago: "day ago",
    days_ago: "days ago",

    // Registry pages
    repositories: "repositories",
    search_placeholder: "Search repositories...",
    no_repos_found: "No repositories found",
    push_first_artifact: "Push your first artifact to see it here",
    name: "Name",
    tags: "Tags",
    versions: "Versions",
    updated: "Updated",

    // Detail pages
    pull_command: "Pull Command",
    install_command: "Install Command",
    maven_dependency: "Maven Dependency",
    total: "total",
    created: "Created",
    published: "Published",
    filename: "Filename",
    files: "files",

    // Bragging footer
    built_for_speed: "Built for speed",
    docker_image: "Docker Image",
    cold_start: "Cold Start",
    memory: "Memory",
    registries_count: "Registries",
    multi_arch: "Multi-arch",
    zero_config: "Zero",
    tagline: "Pure Rust. Single binary. OCI compatible.",

    // Token management
    nav_admin: "Admin",
    nav_tokens: "Tokens",
    token_management: "Token Management",
    token_management_subtitle: "Create and manage API tokens for programmatic access",
    token_create: "Create Token",
    token_revoke: "Revoke",
    token_revoke_confirm: "Are you sure you want to revoke this token?",
    token_description: "Description",
    token_description_placeholder: "e.g. CI/CD Pipeline",
    token_role: "Role",
    token_ttl: "TTL",
    token_ttl_days: "days",
    token_created_success: "Token created successfully. Copy it now — it won't be shown again.",
    token_created_warning: "This token will not be displayed again. Store it securely.",
    token_copy: "Copy",
    token_no_tokens: "No tokens yet. Create one to get started.",
    token_user: "User",
    token_expires: "Expires",
    token_last_used: "Last Used",
    token_never_used: "Never",

    // Pagination
    showing_range: "Showing {start}-{end} of {total} items",
    showing_all: "Showing all {count} items",
    no_more_items: "No more items on this page",
    one_file: "1 file",
    items: "Files",
};

pub static TRANSLATIONS_RU: Translations = Translations {
    // Navigation
    nav_dashboard: "Панель",
    nav_registries: "Реестры",

    // Dashboard
    dashboard_title: "Панель управления",
    dashboard_subtitle: "Обзор всех реестров",
    uptime: "Аптайм",

    // Stats
    stat_downloads: "Загрузки",
    stat_uploads: "Публикации",
    stat_artifacts: "Артефакты",
    stat_cache_hit: "Кэш",
    stat_storage: "Хранилище",
    stats_since_restart: "с момента перезапуска",

    // Registry cards
    active: "АКТИВЕН",
    artifacts: "Артефакты",
    size: "Размер",
    downloads: "Загрузки",
    uploads: "Публикации",

    // Mount points
    mount_points: "Точки монтирования",
    registry: "Реестр",
    mount_path: "Путь",
    proxy_upstream: "Прокси",

    // Activity
    recent_activity: "Последняя активность",
    last_n_events: "Последние 20 событий",
    time: "Время",
    action: "Действие",
    artifact: "Артефакт",
    source: "Источник",
    no_activity: "Нет активности",

    // Relative time
    just_now: "только что",
    min_ago: "мин назад",
    mins_ago: "мин назад",
    hour_ago: "час назад",
    hours_ago: "ч назад",
    day_ago: "день назад",
    days_ago: "дн назад",

    // Registry pages
    repositories: "репозиториев",
    search_placeholder: "Поиск репозиториев...",
    no_repos_found: "Репозитории не найдены",
    push_first_artifact: "Загрузите первый артефакт, чтобы увидеть его здесь",
    name: "Название",
    tags: "Теги",
    versions: "Версии",
    updated: "Обновлено",

    // Detail pages
    pull_command: "Команда загрузки",
    install_command: "Команда установки",
    maven_dependency: "Maven зависимость",
    total: "всего",
    created: "Создан",
    published: "Опубликован",
    filename: "Файл",
    files: "файлов",

    // Bragging footer
    built_for_speed: "Создан для скорости",
    docker_image: "Docker образ",
    cold_start: "Холодный старт",
    memory: "Память",
    registries_count: "Реестров",
    multi_arch: "Мульти-арх",
    zero_config: "Без",
    tagline: "Чистый Rust. Один бинарник. OCI совместимый.",

    // Token management
    nav_admin: "Управление",
    nav_tokens: "Токены",
    token_management: "Управление токенами",
    token_management_subtitle: "Создание и управление API-токенами для программного доступа",
    token_create: "Создать токен",
    token_revoke: "Отозвать",
    token_revoke_confirm: "Вы уверены, что хотите отозвать этот токен?",
    token_description: "Описание",
    token_description_placeholder: "напр. CI/CD Pipeline",
    token_role: "Роль",
    token_ttl: "Срок",
    token_ttl_days: "дней",
    token_created_success: "Токен создан. Скопируйте его сейчас — он больше не будет показан.",
    token_created_warning: "Этот токен не будет показан повторно. Сохраните его надёжно.",
    token_copy: "Копировать",
    token_no_tokens: "Нет токенов. Создайте первый для начала работы.",
    token_user: "Пользователь",
    token_expires: "Истекает",
    token_last_used: "Последнее использование",
    token_never_used: "Не использовался",

    // Pagination
    showing_range: "Показаны {start}-{end} из {total}",
    showing_all: "Показаны все ({count})",
    no_more_items: "На этой странице больше нет элементов",
    one_file: "1 файл",
    items: "Файлы",
};

pub static TRANSLATIONS_ZH: Translations = Translations {
    // Navigation
    nav_dashboard: "仪表盘",
    nav_registries: "注册表",

    // Dashboard
    dashboard_title: "仪表盘",
    dashboard_subtitle: "所有注册表概览",
    uptime: "运行时间",

    // Stats
    stat_downloads: "下载量",
    stat_uploads: "上传量",
    stat_artifacts: "制品数",
    stat_cache_hit: "缓存命中",
    stat_storage: "存储",
    stats_since_restart: "自重启以来",

    // Registry cards
    active: "活跃",
    artifacts: "制品",
    size: "大小",
    downloads: "下载",
    uploads: "上传",

    // Mount points
    mount_points: "挂载点",
    registry: "注册表",
    mount_path: "挂载路径",
    proxy_upstream: "代理上游",

    // Activity
    recent_activity: "最近活动",
    last_n_events: "最近 20 条事件",
    time: "时间",
    action: "操作",
    artifact: "制品",
    source: "来源",
    no_activity: "暂无最近活动",

    // Relative time
    just_now: "刚刚",
    min_ago: "分钟前",
    mins_ago: "分钟前",
    hour_ago: "小时前",
    hours_ago: "小时前",
    day_ago: "天前",
    days_ago: "天前",

    // Registry pages
    repositories: "个仓库",
    search_placeholder: "搜索仓库...",
    no_repos_found: "未找到仓库",
    push_first_artifact: "推送您的第一个制品即可在此查看",
    name: "名称",
    tags: "标签",
    versions: "版本",
    updated: "更新于",

    // Detail pages
    pull_command: "拉取命令",
    install_command: "安装命令",
    maven_dependency: "Maven 依赖",
    total: "共",
    created: "创建于",
    published: "发布于",
    filename: "文件名",
    files: "个文件",

    // Bragging footer
    built_for_speed: "为速度而生",
    docker_image: "Docker 镜像",
    cold_start: "冷启动",
    memory: "内存",
    registries_count: "注册表",
    multi_arch: "多架构",
    zero_config: "零配置",
    tagline: "纯 Rust 实现。单二进制文件。兼容 OCI。",

    // Token management
    nav_admin: "管理",
    nav_tokens: "令牌",
    token_management: "令牌管理",
    token_management_subtitle: "创建和管理用于程序化访问的 API 令牌",
    token_create: "创建令牌",
    token_revoke: "撤销",
    token_revoke_confirm: "确定要撤销此令牌吗？",
    token_description: "描述",
    token_description_placeholder: "例如 CI/CD 流水线",
    token_role: "角色",
    token_ttl: "有效期",
    token_ttl_days: "天",
    token_created_success: "令牌创建成功。请立即复制 — 它将不再显示。",
    token_created_warning: "此令牌将不再显示。请妥善保管。",
    token_copy: "复制",
    token_no_tokens: "暂无令牌。创建一个即可开始使用。",
    token_user: "用户",
    token_expires: "过期时间",
    token_last_used: "最后使用",
    token_never_used: "从未使用",

    // Pagination
    showing_range: "显示第 {start}-{end} 项，共 {total} 项",
    showing_all: "显示全部 {count} 项",
    no_more_items: "此页没有更多项目了",
    one_file: "1 个文件",
    items: "文件",
};

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn from_str_resolves_bare_codes() {
        assert_eq!(Lang::from_str("en"), Lang::En);
        assert_eq!(Lang::from_str("ru"), Lang::Ru);
        assert_eq!(Lang::from_str("zh"), Lang::Zh);
        assert_eq!(Lang::from_str("chinese"), Lang::Zh);
    }

    #[test]
    fn from_str_ignores_region_and_script_subtags() {
        // BCP-47 region/script tags resolve to the primary language.
        assert_eq!(Lang::from_str("zh-CN"), Lang::Zh);
        assert_eq!(Lang::from_str("zh-Hans"), Lang::Zh);
        assert_eq!(Lang::from_str("zh-TW"), Lang::Zh); // only Simplified available
        assert_eq!(Lang::from_str("ru-RU"), Lang::Ru);
        assert_eq!(Lang::from_str("ru_RU.UTF-8"), Lang::Ru);
        assert_eq!(Lang::from_str("en-US"), Lang::En);
    }

    #[test]
    fn from_str_defaults_to_english_for_unknown() {
        assert_eq!(Lang::from_str("fr"), Lang::En);
        assert_eq!(Lang::from_str(""), Lang::En);
    }

    #[test]
    fn code_round_trips_through_from_str() {
        for lang in [Lang::En, Lang::Ru, Lang::Zh] {
            assert_eq!(Lang::from_str(lang.code()), lang);
        }
    }
}
