import { CanonicalFieldSpec } from '../matchers/field-matcher.interface';

/**
 * Canonical project shape used by the UI listing/filters/cards.
 * Anything in a VC that doesn't match these patterns is preserved
 * verbatim under `project.extras` (lossless).
 *
 * Pattern ordering matters: earlier patterns score higher (position weight),
 * so put the most specific / authoritative patterns first.
 */
export const CANONICAL_PROJECT_FIELDS: CanonicalFieldSpec[] = [
    {
        key: 'projectId',
        type: 'string',
        required: true,
        namePatterns: [
            /^project[_-]?id$/i,
            /^project[_-]?identifier$/i,
            /^vcs[_-]?id$/i,
            /^registry[_-]?id$/i,
            /^uniqu(e)?[_-]?id$/i,
            /^id$/i,                                  // generic fallback
        ],
    },
    {
        key: 'name',
        type: 'string',
        required: true,
        multiLanguage: true,
        namePatterns: [
            /^project[_-]?name$/i,
            /^display[_-]?name$/i,
            /^project[_-]?label$/i,
            /^title$/i,
            /^name$/i,
            /^label$/i,
        ],
    },
    {
        key: 'description',
        type: 'string',
        multiLanguage: true,
        namePatterns: [
            /^project[_-]?description$/i,
            /^project[_-]?summary$/i,
            /^summary[_-]?description$/i,
            /^description[_-]?of[_-]?project[_-]?area$/i,
            /^description$/i,
            /^summary$/i,
            /^abstract$/i,
        ],
    },
    {
        key: 'country',
        type: 'string',
        namePatterns: [
            /^host[_-]?country$/i,
            /^country[_-]?name$/i,
            /^country$/i,
            /^nation$/i,
        ],
    },
    {
        key: 'countryCode',
        type: 'string',
        namePatterns: [
            /^country[_-]?code$/i,
            /^iso[_-]?country[_-]?code$/i,
            /^iso[_-]?2[_-]?country$/i,
            /^iso[_-]?country$/i,
        ],
    },
    {
        key: 'region',
        type: 'string',
        namePatterns: [
            /^state[_-]?province$/i,
            /^region$/i,
            /^state$/i,
            /^province$/i,
            /^subnational$/i,
            /^continent$/i,                           // last resort
        ],
    },
    {
        key: 'latitude',
        type: 'number',
        namePatterns: [
            /^latitude$/i,
            /^lat$/i,
            /^geo[_-]?lat$/i,
            /^lat[_-]?coord(inate)?$/i,
        ],
    },
    {
        key: 'longitude',
        type: 'number',
        namePatterns: [
            /^longitude$/i,
            /^lng$/i,
            /^lon$/i,
            /^geo[_-]?l(o)?ng$/i,
            /^lng[_-]?coord(inate)?$/i,
        ],
    },
    {
        key: 'startDate',
        type: 'date',
        namePatterns: [
            /^crediting[_-]?start[_-]?date$/i,
            /^crediting[_-]?period[_-]?start/i,
            /^project[_-]?start[_-]?date$/i,
            /^project[_-]?registration[_-]?date$/i,
            /^implementation[_-]?start/i,
            /^period[_-]?start$/i,
            /^start[_-]?date$/i,
        ],
    },
    {
        key: 'endDate',
        type: 'date',
        namePatterns: [
            /^crediting[_-]?end[_-]?date$/i,
            /^crediting[_-]?period[_-]?end/i,
            /^project[_-]?end[_-]?date$/i,
            /^implementation[_-]?end/i,
            /^period[_-]?end$/i,
            /^end[_-]?date$/i,
        ],
    },
    {
        key: 'vintage',
        type: 'string',
        namePatterns: [
            /^vintage[_-]?of[_-]?credits?$/i,
            /^vintage$/i,
            /^reporting[_-]?year$/i,
            /^crediting[_-]?period$/i,
            /^year$/i,
        ],
    },
    {
        key: 'proponentName',
        type: 'string',
        multiLanguage: true,
        namePatterns: [
            /^project[_-]?developer$/i,
            /^cv[_-]?developer$/i,
            /^developer$/i,
            /^project[_-]?proponent$/i,
            /^proponents?$/i,                         // singular or plural
            /^pp[_-]?organization[_-]?name$/i,
            /^operator$/i,
            /^company[_-]?name$/i,
            /^entity[_-]?name$/i,
            /^owner$/i,                               // last resort — owner often = record-owner not project sponsor
        ],
    },
    {
        key: 'status',
        type: 'string',
        namePatterns: [
            /^project[_-]?status$/i,
            /^lifecycle[_-]?status$/i,
            /^status$/i,
            /^stage$/i,
            /^state$/i,
        ],
    },
    {
        key: 'methodologyTag',
        type: 'string',
        namePatterns: [
            /^methodology$/i,
            /^methodology[_-]?(id|tag|reference)$/i,
            /^title[_-]?and[_-]?reference[_-]?of[_-]?methodologies$/i,
            /^quantification[_-]?method$/i,
            /^protocol$/i,
            /^standard$/i,
        ],
    },
    {
        key: 'sector',
        type: 'string',
        namePatterns: [
            /^sector$/i,
            /^subsector$/i,
            /^industry$/i,
            /^industry[_-]?sector$/i,
        ],
    },
    {
        key: 'category',
        type: 'string',
        namePatterns: [
            /^category$/i,
            /^classification$/i,
            /^class$/i,
            /^scope$/i,
        ],
    },
    {
        key: 'projectType',
        type: 'string',
        namePatterns: [
            /^project[_-]?type$/i,
            /^offset[_-]?type$/i,
            /^credit[_-]?type$/i,
            /^type[_-]?of[_-]?project$/i,
            /^project[_-]?activity[_-]?type$/i,
        ],
    },
];
