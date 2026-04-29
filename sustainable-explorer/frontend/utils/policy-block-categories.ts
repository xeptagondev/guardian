export type BlockCategory =
    | 'ui'
    | 'role'
    | 'schema'
    | 'token'
    | 'info'
    | 'logic'
    | 'integration'
    | 'unknown';

const CATEGORY_BY_BLOCK_TYPE: Record<string, BlockCategory> = {
    // UI / containers
    interfaceContainerBlock: 'ui',
    tabsBlock: 'ui',
    stepBlock: 'ui',
    selectiveAttributesBlock: 'ui',
    buttonBlock: 'ui',
    interfaceStepBlock: 'ui',
    interfaceDocumentsSourceBlock: 'ui',
    interfaceActionBlock: 'ui',
    paginationAddon: 'ui',

    // Role / permissions
    policyRolesBlock: 'role',
    groupBlock: 'role',
    groupManagerBlock: 'role',

    // Schema-driven
    requestVcDocumentBlock: 'schema',
    sendToGuardianBlock: 'schema',
    documentsSourceBlock: 'schema',
    documentValidatorBlock: 'schema',
    filtersAddonBlock: 'schema',
    historyAddon: 'schema',
    documentSignatureBlock: 'schema',
    setRelationshipsBlock: 'schema',
    splitBlock: 'schema',

    // Token
    createTokenBlock: 'token',
    mintTokenBlock: 'token',
    mintDocumentBlock: 'token',
    retirementBlock: 'token',
    retirementDocumentBlock: 'token',
    tokenActionBlock: 'token',
    tokenConfirmationBlock: 'token',
    tokenOperationAddon: 'token',

    // Info / reports
    informationBlock: 'info',
    reportItemBlock: 'info',
    reportBlock: 'info',
    impactAddon: 'info',
    notificationBlock: 'info',

    // Logic
    customLogicBlock: 'logic',
    calculateContainerBlock: 'logic',
    calculateMathAddon: 'logic',
    calculateMathVariables: 'logic',
    switchBlock: 'logic',
    expressionBlock: 'logic',
    aggregateDocumentBlock: 'logic',

    // Integration
    externalDataBlock: 'integration',
    httpRequestBlock: 'integration',
    externalTopicBlock: 'integration',
    messagesReportBlock: 'integration',
    revokeBlock: 'integration',
    revocationBlock: 'integration',
};

export function categorizeBlockType(blockType: string | undefined | null): BlockCategory {
    if (!blockType) return 'unknown';
    return CATEGORY_BY_BLOCK_TYPE[blockType] ?? 'unknown';
}

export interface CategoryStyle {
    label: string;
    bg: string;
    border: string;
    dot: string;
    text: string;
}

export const CATEGORY_STYLES: Record<BlockCategory, CategoryStyle> = {
    ui:          { label: 'UI',          bg: 'bg-blue-50',   border: 'border-blue-300',   dot: 'bg-blue-500',   text: 'text-blue-900' },
    role:        { label: 'Role',        bg: 'bg-purple-50', border: 'border-purple-300', dot: 'bg-purple-500', text: 'text-purple-900' },
    schema:      { label: 'Schema',      bg: 'bg-emerald-50',border: 'border-emerald-300',dot: 'bg-emerald-500',text: 'text-emerald-900' },
    token:       { label: 'Token',       bg: 'bg-amber-50',  border: 'border-amber-300',  dot: 'bg-amber-500',  text: 'text-amber-900' },
    info:        { label: 'Info',        bg: 'bg-slate-50',  border: 'border-slate-300',  dot: 'bg-slate-500',  text: 'text-slate-900' },
    logic:       { label: 'Logic',       bg: 'bg-rose-50',   border: 'border-rose-300',   dot: 'bg-rose-500',   text: 'text-rose-900' },
    integration: { label: 'Integration', bg: 'bg-cyan-50',   border: 'border-cyan-300',   dot: 'bg-cyan-500',   text: 'text-cyan-900' },
    unknown:     { label: 'Unknown',     bg: 'bg-gray-50',   border: 'border-gray-300',   dot: 'bg-gray-400',   text: 'text-gray-700' },
};
