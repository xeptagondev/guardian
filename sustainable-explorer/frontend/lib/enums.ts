// ---------------------------------------------------------------------------
// Sectors — official CDM/VCS taxonomy
// ---------------------------------------------------------------------------

export const SECTORS = [
    'Energy',
    'Industrial Process',
    'Land Use & Forestry',
    'Waste',
    'Fugitive Emissions',
    'Transport',
    'Others',
] as const;

export type Sector = typeof SECTORS[number];

export const SECTOR_COLORS: Record<string, string> = {
    'Energy':              'hsl(142, 76%, 36%)',
    'Industrial Process':  'hsl(25,  95%, 53%)',
    'Land Use & Forestry': 'hsl(47,  96%, 53%)',
    'Waste':               'hsl(349, 89%, 60%)',
    'Fugitive Emissions':  'hsl(197, 37%, 24%)',
    'Transport':           'hsl(217, 71%, 53%)',
    'Others':              'hsl(220, 13%, 69%)',
};

export function getSectorColor(sector: string): string {
    return SECTOR_COLORS[sector] ?? 'hsl(220, 13%, 69%)';
}

// ---------------------------------------------------------------------------
// Project statuses
// ---------------------------------------------------------------------------

export const PROJECT_STATUSES = [
    'Issuing',
    'Under Validation',
    'Registered',
    'Verified',
    'Completed',
] as const;

export type ProjectStatus = typeof PROJECT_STATUSES[number];
