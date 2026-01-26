/// Internationalization support for the UI
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Lang {
    #[default]
    En,
    Ru,
}

impl Lang {
    pub fn from_str(s: &str) -> Self {
        match s.to_lowercase().as_str() {
            "ru" | "rus" | "russian" => Lang::Ru,
            _ => Lang::En,
        }
    }

    pub fn code(&self) -> &'static str {
        match self {
            Lang::En => "en",
            Lang::Ru => "ru",
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
}

pub fn get_translations(lang: Lang) -> &'static Translations {
    match lang {
        Lang::En => &TRANSLATIONS_EN,
        Lang::Ru => &TRANSLATIONS_RU,
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
};
