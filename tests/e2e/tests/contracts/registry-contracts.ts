/**
 * UI Contract Definitions for NORA Registry
 *
 * Single source of truth for what each registry page MUST render.
 * Selectors verified against nora-registry/src/ui/templates.rs and components.rs.
 */

// --- Types ---

export interface ListPageContract {
  /** URL slug: /ui/{slug} */
  slug: string;
  /** Expected H1 title text */
  title: string;
  /** Column headers in the list table (Name is always first) */
  columnHeaders: string[];
  /** Label for the count column (Tags, Versions, Items) */
  countColumnLabel: string;
  /** Whether the registry uses hierarchical (directory) browsing */
  isHierarchical: boolean;
  /** Whether a search input is expected */
  hasSearch: boolean;
  /** HTMX search endpoint: /api/ui/{slug}/search */
  searchEndpoint: string;
}

export interface DetailPageContract {
  /** URL slug used in breadcrumb link: /ui/{slug} */
  slug: string;
  /** Text shown in the breadcrumb root link back to list */
  breadcrumbRootText: string;
  /** Whether an install command section is rendered */
  hasInstallCommand: boolean;
  /** Label for the install section (e.g. "Pull Command", "Install") */
  installSectionLabel?: string;
  /** Pattern the install command must match */
  installCommandPattern?: RegExp;
  /** Column headers in the detail/versions table */
  tableColumnHeaders: string[];
  /** Whether a metadata panel is rendered */
  hasMetadataPanel: boolean;
  /** Whether version rows are clickable (NuGet-style interactive selection) */
  hasClickableVersionRows: boolean;
}

export interface RegistryContract {
  /** Registry type slug */
  slug: string;
  /** Human-readable display name (used in H1 titles, registry cards) */
  displayName: string;
  /** Short name shown in the sidebar navigation */
  sidebarName: string;
  /** List page contract */
  list: ListPageContract;
  /** Detail page contract */
  detail: DetailPageContract;
}

export interface DashboardContract {
  /** CSS selectors for stats cards */
  statsIds: string[];
  /** Selector for registry card links */
  registryCardSelector: string;
  /** Whether mount points table is expected */
  hasMountPointsTable: boolean;
  /** Whether activity log section is expected */
  hasActivityLog: boolean;
}

// --- Registry Contracts ---

export const REGISTRIES: RegistryContract[] = [
  {
    slug: 'docker',
    displayName: 'Docker Registry',
    sidebarName: 'Docker',
    list: {
      slug: 'docker',
      title: 'Docker Registry',
      columnHeaders: ['Name', 'Tags', 'Size', 'Updated'],
      countColumnLabel: 'Tags',
      isHierarchical: false,
      hasSearch: true,
      searchEndpoint: '/api/ui/docker/search',
    },
    detail: {
      slug: 'docker',
      breadcrumbRootText: 'Docker',
      hasInstallCommand: true,
      installSectionLabel: 'Pull Command',
      installCommandPattern: /docker pull .+\/.+/,
      tableColumnHeaders: ['Tag', 'Size', 'Created'],
      hasMetadataPanel: false,
      hasClickableVersionRows: false,
    },
  },
  {
    slug: 'npm',
    displayName: 'npm Registry',
    sidebarName: 'npm',
    list: {
      slug: 'npm',
      title: 'npm Registry',
      columnHeaders: ['Name', 'Versions', 'Size', 'Updated'],
      countColumnLabel: 'Versions',
      isHierarchical: false,
      hasSearch: true,
      searchEndpoint: '/api/ui/npm/search',
    },
    detail: {
      slug: 'npm',
      breadcrumbRootText: 'npm',
      hasInstallCommand: true,
      installSectionLabel: 'Install Command',
      installCommandPattern: /npm install .+ --registry .+\/npm/,
      tableColumnHeaders: ['Versions', 'Size', 'Published'],
      hasMetadataPanel: false,
      hasClickableVersionRows: false,
    },
  },
  {
    slug: 'maven',
    displayName: 'Maven Repository',
    sidebarName: 'Maven',
    list: {
      slug: 'maven',
      title: 'Maven Repository',
      columnHeaders: ['Name', 'Files', 'Size', 'Updated'],
      countColumnLabel: 'Files',
      isHierarchical: true,
      hasSearch: true,
      searchEndpoint: '/api/ui/maven/search',
    },
    detail: {
      slug: 'maven',
      breadcrumbRootText: 'Maven',
      hasInstallCommand: true,
      installSectionLabel: 'Maven Dependency',
      installCommandPattern: /<dependency>/,
      tableColumnHeaders: ['Filename', 'Size'],
      hasMetadataPanel: false,
      hasClickableVersionRows: false,
    },
  },
  {
    slug: 'cargo',
    displayName: 'Cargo Registry',
    sidebarName: 'Cargo',
    list: {
      slug: 'cargo',
      title: 'Cargo Registry',
      columnHeaders: ['Name', 'Versions', 'Size', 'Updated'],
      countColumnLabel: 'Versions',
      isHierarchical: false,
      hasSearch: true,
      searchEndpoint: '/api/ui/cargo/search',
    },
    detail: {
      slug: 'cargo',
      breadcrumbRootText: 'Cargo Registry',
      hasInstallCommand: true,
      installSectionLabel: 'Install Command',
      installCommandPattern: /cargo add .+/,
      tableColumnHeaders: ['Versions', 'Size', 'Published'],
      hasMetadataPanel: false,
      hasClickableVersionRows: false,
    },
  },
  {
    slug: 'pypi',
    displayName: 'PyPI Repository',
    sidebarName: 'PyPI',
    list: {
      slug: 'pypi',
      title: 'PyPI Repository',
      columnHeaders: ['Name', 'Versions', 'Size', 'Updated'],
      countColumnLabel: 'Versions',
      isHierarchical: false,
      hasSearch: true,
      searchEndpoint: '/api/ui/pypi/search',
    },
    detail: {
      slug: 'pypi',
      breadcrumbRootText: 'PyPI Repository',
      hasInstallCommand: true,
      installSectionLabel: 'Install Command',
      installCommandPattern: /pip install .+ --index-url .+\/simple/,
      tableColumnHeaders: ['Versions', 'Size', 'Published'],
      hasMetadataPanel: false,
      hasClickableVersionRows: false,
    },
  },
  {
    slug: 'go',
    displayName: 'Go Modules',
    sidebarName: 'Go',
    list: {
      slug: 'go',
      title: 'Go Modules',
      columnHeaders: ['Name', 'Files', 'Size', 'Updated'],
      countColumnLabel: 'Files',
      isHierarchical: true,
      hasSearch: true,
      searchEndpoint: '/api/ui/go/search',
    },
    detail: {
      slug: 'go',
      breadcrumbRootText: 'Go Modules',
      hasInstallCommand: true,
      installSectionLabel: 'Install Command',
      installCommandPattern: /GOPROXY=.+\/go.+go get .+/,
      tableColumnHeaders: ['Versions', 'Size', 'Published'],
      hasMetadataPanel: false,
      hasClickableVersionRows: false,
    },
  },
  {
    slug: 'raw',
    displayName: 'Raw Storage',
    sidebarName: 'Raw',
    list: {
      slug: 'raw',
      title: 'Raw Storage',
      columnHeaders: ['Name', 'Files', 'Size', 'Updated'],
      countColumnLabel: 'Files',
      isHierarchical: true,
      hasSearch: true,
      searchEndpoint: '/api/ui/raw/search',
    },
    detail: {
      slug: 'raw',
      breadcrumbRootText: 'Raw Storage',
      hasInstallCommand: true,
      installSectionLabel: 'Install Command',
      installCommandPattern: /curl -O .+\/raw\/.+/,
      tableColumnHeaders: ['Filename', 'Size', 'Published'],
      hasMetadataPanel: false,
      hasClickableVersionRows: false,
    },
  },
  {
    slug: 'gems',
    displayName: 'RubyGems',
    sidebarName: 'RubyGems',
    list: {
      slug: 'gems',
      title: 'RubyGems',
      columnHeaders: ['Name', 'Versions', 'Size', 'Updated'],
      countColumnLabel: 'Versions',
      isHierarchical: false,
      hasSearch: true,
      searchEndpoint: '/api/ui/gems/search',
    },
    detail: {
      slug: 'gems',
      breadcrumbRootText: 'RubyGems',
      hasInstallCommand: true,
      installSectionLabel: 'Install Command',
      installCommandPattern: /gem install .+ --source .+\/gems/,
      tableColumnHeaders: ['Versions', 'Size', 'Published'],
      hasMetadataPanel: false,
      hasClickableVersionRows: false,
    },
  },
  {
    slug: 'terraform',
    displayName: 'Terraform Registry',
    sidebarName: 'Terraform',
    list: {
      slug: 'terraform',
      title: 'Terraform Registry',
      columnHeaders: ['Name', 'Versions', 'Size', 'Updated'],
      countColumnLabel: 'Versions',
      isHierarchical: false,
      hasSearch: true,
      searchEndpoint: '/api/ui/terraform/search',
    },
    detail: {
      slug: 'terraform',
      breadcrumbRootText: 'Terraform Registry',
      hasInstallCommand: true,
      installSectionLabel: 'Install Command',
      installCommandPattern: /source\s*=\s*".+\/terraform\/.+"/,
      tableColumnHeaders: ['Versions', 'Size', 'Published'],
      hasMetadataPanel: false,
      hasClickableVersionRows: false,
    },
  },
  {
    slug: 'ansible',
    displayName: 'Ansible Galaxy',
    sidebarName: 'Ansible',
    list: {
      slug: 'ansible',
      title: 'Ansible Galaxy',
      columnHeaders: ['Name', 'Versions', 'Size', 'Updated'],
      countColumnLabel: 'Versions',
      isHierarchical: false,
      hasSearch: true,
      searchEndpoint: '/api/ui/ansible/search',
    },
    detail: {
      slug: 'ansible',
      breadcrumbRootText: 'Ansible Galaxy',
      hasInstallCommand: true,
      installSectionLabel: 'Install Command',
      installCommandPattern: /ansible-galaxy collection install .+/,
      tableColumnHeaders: ['Versions', 'Size', 'Published'],
      hasMetadataPanel: false,
      hasClickableVersionRows: false,
    },
  },
  {
    slug: 'nuget',
    displayName: 'NuGet Gallery',
    sidebarName: 'NuGet',
    list: {
      slug: 'nuget',
      title: 'NuGet Gallery',
      columnHeaders: ['Name', 'Versions', 'Size', 'Updated'],
      countColumnLabel: 'Versions',
      isHierarchical: false,
      hasSearch: true,
      searchEndpoint: '/api/ui/nuget/search',
    },
    detail: {
      slug: 'nuget',
      breadcrumbRootText: 'NuGet Gallery',
      hasInstallCommand: true,
      installSectionLabel: 'Install Command',
      installCommandPattern: /dotnet add package .+/,
      tableColumnHeaders: ['Versions', 'Size', 'Published'],
      hasMetadataPanel: false,
      hasClickableVersionRows: true,
    },
  },
  {
    slug: 'pub',
    displayName: 'Pub (Dart/Flutter)',
    sidebarName: 'pub.dev',
    list: {
      slug: 'pub',
      title: 'Pub (Dart/Flutter)',
      columnHeaders: ['Name', 'Versions', 'Size', 'Updated'],
      countColumnLabel: 'Versions',
      isHierarchical: false,
      hasSearch: true,
      searchEndpoint: '/api/ui/pub/search',
    },
    detail: {
      slug: 'pub',
      breadcrumbRootText: 'Pub',
      hasInstallCommand: true,
      installSectionLabel: 'Install Command',
      installCommandPattern: /hosted:\s*.+\/pub/,
      tableColumnHeaders: ['Versions', 'Size', 'Published'],
      hasMetadataPanel: false,
      hasClickableVersionRows: false,
    },
  },
  {
    slug: 'conan',
    displayName: 'Conan (C/C++)',
    sidebarName: 'Conan',
    list: {
      slug: 'conan',
      title: 'Conan (C/C++)',
      columnHeaders: ['Name', 'Versions', 'Size', 'Updated'],
      countColumnLabel: 'Versions',
      isHierarchical: false,
      hasSearch: true,
      searchEndpoint: '/api/ui/conan/search',
    },
    detail: {
      slug: 'conan',
      breadcrumbRootText: 'Conan (C/C++)',
      hasInstallCommand: true,
      installSectionLabel: 'Install Command',
      installCommandPattern: /conan install .+/,
      tableColumnHeaders: ['Versions', 'Size', 'Published'],
      hasMetadataPanel: false,
      hasClickableVersionRows: false,
    },
  },
];

// --- Dashboard Contract ---

export const DASHBOARD: DashboardContract = {
  statsIds: [
    '#stat-downloads',
    '#stat-uploads',
    '#stat-artifacts',
    '#stat-cache-hit',
    '#stat-storage',
  ],
  registryCardSelector: 'a[id^="registry-"]',
  hasMountPointsTable: true,
  hasActivityLog: true,
};

// --- Helpers ---

/** Get a registry contract by slug */
export function getRegistry(slug: string): RegistryContract {
  const r = REGISTRIES.find((r) => r.slug === slug);
  if (!r) throw new Error(`Unknown registry slug: ${slug}`);
  return r;
}

/** All registry slugs */
export const ALL_SLUGS = REGISTRIES.map((r) => r.slug);

/** Sidebar nav labels — short names shown in sidebar for all registries + Dashboard */
export const SIDEBAR_LABELS = ['Dashboard', ...REGISTRIES.map((r) => r.sidebarName)];
