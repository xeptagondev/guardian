import { Logger } from '@nestjs/common';
import { DataSource } from 'typeorm';

type MappingField = {
    fieldName: string;
    description: string;
    keywords: string[];
};

type MappingResult = {
    fieldName: string;
    matchedIndex: string | null;
};

type ProjectFieldMap = Record<string, string | null>;

type SchemaLeafDescriptions = {
    descriptions: Record<string, string>;
    paths: Record<string, string>;
};

type PolicySchemaRow = {
    name: string | null;
    description: string | null;
    document: unknown;
    rawSchema: unknown;
};

type SchemaNode = {
    key: string;
    title?: string;
    description?: string;
    children?: SchemaNode[];
};

const logger = new Logger('LlmBasedMapper');
const RETRY_INVALID_JSON_WITH_LLM = true;

/**
 * Field mapping method configuration.
 * Environment variable: FIELD_MAPPING_METHOD
 * Options:
 *   - 'llm' (requires API keys: GEMINI_API_KEY or OPENAI_API_KEY)
 *   - 'heuristic' (simple keyword-based fallback, no API keys needed)
 * Default: 'heuristic'
 */
const FIELD_MAPPING_METHOD = (process.env.FIELD_MAPPING_METHOD || 'heuristic').toLowerCase();
const USE_LLM_MAPPING = FIELD_MAPPING_METHOD === 'llm';

const MAPPING_SYSTEM_PROMPT = `You are given:
1) A list of target business fields.
2) A dictionary of schema leaf descriptions keyed by numeric index.

Your task is to map each target field to the single best matching description index.

Rules:
1. Use semantic meaning from fieldName, field description, and keywords.
2. Match only against the provided leaf descriptions.
3. Return the numeric index as a string in matchedIndex.
4. If no good match exists, return null.
5. Do not invent indexes.
6. Be strict and avoid weak matches.

Output format (STRICT JSON):
[
	{
		"fieldName": "string",
		"matchedIndex": "string | null"
	}
]`;

const PROJECT_TARGET_FIELDS: MappingField[] = [
    { fieldName: 'Project Title', description: 'Official name or title of the project', keywords: ['title', 'project', 'name'] },
    { fieldName: 'Country', description: 'Country where the project is implemented or located', keywords: ['country', 'location', 'host'] },
    { fieldName: 'Registry', description: 'Carbon or environmental registry system where the project is registered (e.g., Verra, Gold Standard)', keywords: ['registry', 'standard', 'program'] },
    { fieldName: 'Project Developer', description: 'Organization, company, or entity responsible for developing or implementing the project', keywords: ['developer', 'proponent', 'entity'] },
    { fieldName: 'Sector', description: 'Industry or sector classification of the project (e.g., energy, forestry, agriculture)', keywords: ['sector', 'type', 'category'] },
    { fieldName: 'Status', description: 'Current lifecycle status of the project such as proposed, registered, active, or retired', keywords: ['status', 'stage', 'state'] },
    { fieldName: 'SDGs', description: 'List of United Nations Sustainable Development Goals (SDGs) that the project contributes to or supports', keywords: ['sdg', 'goals', 'sustainable'] },
];

function isRetryableHighDemandError(error: unknown): boolean {
    const message = error instanceof Error ? error.message : String(error ?? '');
    const status = typeof (error as { status?: unknown })?.status === 'number'
        ? (error as { status: number }).status
        : undefined;

    return status === 429 || status === 503 || message.includes('high demand') || message.includes('UNAVAILABLE');
}

async function generateContentWithRetry(task: () => Promise<string>, maxRetries = 3): Promise<string> {
    for (let attempt = 1; attempt <= maxRetries + 1; attempt += 1) {
        try {
            return await task();
        } catch (error) {
            if (!isRetryableHighDemandError(error) || attempt === maxRetries + 1) {
                throw error;
            }

            logger.warn(`Provider error on attempt ${attempt}: ${(error as Error).message}`);
            await new Promise((resolve) => setTimeout(resolve, 1000 * attempt));
        }
    }

    throw new Error('Unreachable retry state.');
}

function stripCodeFences(text: string): string {
    return text.trim().replace(/^```(?:json|javascript|js)?\s*/i, '').replace(/\s*```$/i, '').trim();
}

function parseModelOutput(text: string): MappingResult[] {
    const parsed = JSON.parse(stripCodeFences(text)) as unknown;
    if (!Array.isArray(parsed)) {
        throw new Error('Model output is not an array.');
    }

    return parsed.map((item) => {
        const row = item as Record<string, unknown>;
        return {
            fieldName: typeof row.fieldName === 'string' ? row.fieldName : '',
            matchedIndex: typeof row.matchedIndex === 'string' || row.matchedIndex === null
                ? (row.matchedIndex as string | null)
                : null,
        };
    });
}

function buildJsonRetryMessage(modelOutput: string): string {
    return `Convert the following response into strict JSON only. Return an array of objects with exactly these keys: fieldName and matchedIndex. Do not include markdown fences, commentary, or any extra keys. If no match is found, use null for matchedIndex.\n\nPrevious response:\n${modelOutput}`;
}

function parsePolicyTopicId(methodologyBusinessData: unknown): string | null {
    if (!methodologyBusinessData || typeof methodologyBusinessData !== 'object') {
        return null;
    }

    const data = methodologyBusinessData as Record<string, unknown>;
    const directTopicId = data.topicId;
    if (typeof directTopicId === 'string' && directTopicId.trim()) {
        return directTopicId.trim();
    }

    const options = data.options;
    if (options && typeof options === 'object') {
        const nestedTopicId = (options as Record<string, unknown>).topicId;
        if (typeof nestedTopicId === 'string' && nestedTopicId.trim()) {
            return nestedTopicId.trim();
        }
    }

    return null;
}

function resolveSchemaRef(ref: string, defs: Record<string, unknown>): Record<string, unknown> | null {
    if (!ref) return null;

    const direct = defs[ref];
    if (direct && typeof direct === 'object') {
        return direct as Record<string, unknown>;
    }

    const match = ref.match(/#\/(?:\$defs|definitions)\/([^/]+)$/);
    if (match) {
        const resolved = defs[match[1]];
        if (resolved && typeof resolved === 'object') {
            return resolved as Record<string, unknown>;
        }
    }

    return null;
}

function transformSchema(schema: Record<string, unknown>): SchemaNode {
    const defs = (schema.$defs ?? schema.definitions ?? {}) as Record<string, unknown>;

    function processNode(node: Record<string, unknown>, key = 'root'): SchemaNode {
        const title = typeof node.title === 'string' && node.title.trim() ? node.title.trim() : key;
        const description = typeof node.description === 'string' ? node.description.trim() : '';

        const result: SchemaNode = { key };
        if (title !== key) result.title = title;
        if (description) result.description = description;

        if (!node.properties || typeof node.properties !== 'object') return result;

        const children: SchemaNode[] = [];
        for (const [propKey, propValue] of Object.entries(node.properties as Record<string, unknown>)) {
            if (['@context', 'type', 'id'].includes(propKey) || !propValue || typeof propValue !== 'object') {
                continue;
            }

            const propNode = propValue as Record<string, unknown>;
            const current = typeof propNode.$ref === 'string'
                ? resolveSchemaRef(propNode.$ref, defs) ?? propNode
                : propNode;

            const childNode = processNode(current, propKey);
            const propTitle = typeof propNode.title === 'string' && propNode.title.trim() ? propNode.title.trim() : childNode.key;
            const propDesc = typeof propNode.description === 'string' && propNode.description.trim() ? propNode.description.trim() : childNode.description;

            if (propTitle !== childNode.key) {
                childNode.title = propTitle;
            } else {
                delete childNode.title;
            }

            if (propDesc) {
                childNode.description = propDesc;
            }

            children.push(childNode);
        }

        if (children.length > 0) {
            result.children = children;
        }

        return result;
    }

    return processNode(schema);
}

function filterLeavesByKeywords(tree: SchemaNode | null, fieldsConfig: MappingField[]): SchemaNode | null {
    if (!tree) return null;

    const keywords = fieldsConfig
        .flatMap((field) => field.keywords)
        .map((keyword) => String(keyword).toLowerCase().trim())
        .filter(Boolean);

    function nodeText(node: SchemaNode): string {
        return [node.key, node.title, node.description].filter(Boolean).join(' ').toLowerCase();
    }

    function leafMatches(node: SchemaNode): boolean {
        const text = nodeText(node);
        return keywords.some((keyword) => text.includes(keyword));
    }

    function prune(node: SchemaNode): SchemaNode | null {
        const children = node.children ?? [];
        const hasChildren = children.length > 0;
        if (!hasChildren) {
            return leafMatches(node) ? { ...node } : null;
        }

        const filteredChildren = children.map((child) => prune(child)).filter((child): child is SchemaNode => Boolean(child));
        const nextNode: SchemaNode = { ...node };
        if (filteredChildren.length > 0) {
            nextNode.children = filteredChildren;
        } else {
            delete nextNode.children;
        }

        return nextNode;
    }

    return prune(tree);
}

function extractLeafNodes(tree: SchemaNode | null): SchemaNode[] {
    const leaves: SchemaNode[] = [];

    function traverse(node: SchemaNode, path = ''): void {
        const children = node.children ?? [];
        const hasChildren = children.length > 0;
        if (!hasChildren) {
            leaves.push({
                key: node.key,
                ...(path ? { title: path } : {}),
                ...(node.description ? { description: node.description } : {}),
            });
            return;
        }

        children.forEach((child) => {
            const childPath = path ? `${path}.${child.key}` : child.key;
            traverse(child, childPath);
        });
    }

    if (tree) {
        const initialPath = tree.key && tree.key !== 'root' ? tree.key : '';
        traverse(tree, initialPath);
    }

    return leaves;
}

function compressLeafDescriptions(leaves: SchemaNode[]): SchemaLeafDescriptions {
    const descriptions: Record<string, string> = {};
    const paths: Record<string, string> = {};

    leaves.forEach((leaf, index) => {
        descriptions[index] = leaf.description || '';
        paths[index] = leaf.title?.trim() || leaf.key;
    });

    return { descriptions, paths };
}

async function getModelResponse({ systemPrompt, userMessage }: { systemPrompt: string; userMessage: string }): Promise<string> {
    const provider = (process.env.AI_PROVIDER || 'gemini').toLowerCase();

    if (!['gemini', 'openai'].includes(provider)) {
        throw new Error("AI_PROVIDER must be either 'gemini' or 'openai'.");
    }

    if (provider === 'gemini') {
        const apiKey = process.env.GEMINI_API_KEY;
        if (!apiKey) {
            throw new Error('GEMINI_API_KEY environment variable is not set.');
        }

        const model = process.env.GEMINI_MODEL || 'gemini-2.5-flash';
        return generateContentWithRetry(async () => {
            const response = await fetch(
                `https://generativelanguage.googleapis.com/v1beta/models/${encodeURIComponent(model)}:generateContent?key=${encodeURIComponent(apiKey)}`,
                {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({
                        systemInstruction: { parts: [{ text: systemPrompt }] },
                        contents: [{ role: 'user', parts: [{ text: userMessage }] }],
                        generationConfig: { temperature: 0 },
                    }),
                },
            );

            const raw = await response.text();
            if (!response.ok) {
                const error = new Error(raw || `Gemini request failed with status ${response.status}`) as Error & { status?: number };
                error.status = response.status;
                throw error;
            }

            const payload = JSON.parse(raw) as {
                candidates?: Array<{ content?: { parts?: Array<{ text?: string }> } }>;
            };

            return payload.candidates?.[0]?.content?.parts?.map((part) => part.text ?? '').join('') || '';
        });
    }

    const apiKey = process.env.OPENAI_API_KEY;
    if (!apiKey) {
        throw new Error('OPENAI_API_KEY environment variable is not set.');
    }

    const model = process.env.OPENAI_MODEL || 'gpt-4.1-mini';
    return generateContentWithRetry(async () => {
        const response = await fetch('https://api.openai.com/v1/chat/completions', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                Authorization: `Bearer ${apiKey}`,
            },
            body: JSON.stringify({
                model,
                messages: [
                    { role: 'system', content: systemPrompt },
                    { role: 'user', content: userMessage },
                ],
                temperature: 0,
            }),
        });

        const raw = await response.text();
        if (!response.ok) {
            const error = new Error(raw || `OpenAI request failed with status ${response.status}`) as Error & { status?: number };
            error.status = response.status;
            throw error;
        }

        const payload = JSON.parse(raw) as { choices?: Array<{ message?: { content?: string } }> };
        return payload.choices?.[0]?.message?.content || '';
    });
}

async function buildSchemaLeafDescriptions(schema: Record<string, unknown>, fieldsData: MappingField[]): Promise<SchemaLeafDescriptions> {
    const schemaTree = transformSchema(schema);
    const keywordFilteredSchemaTree = filterLeavesByKeywords(schemaTree, fieldsData) ?? schemaTree;
    return compressLeafDescriptions(extractLeafNodes(keywordFilteredSchemaTree));
}

function buildFallbackTargetFields(methodologyBusinessData: unknown): MappingField[] {
    const data = methodologyBusinessData && typeof methodologyBusinessData === 'object'
        ? (methodologyBusinessData as Record<string, unknown>)
        : {};
    const options = data.options && typeof data.options === 'object'
        ? (data.options as Record<string, unknown>)
        : {};

    const methodologyContext = [data.description, options.name, options.description, data.status]
        .filter((value): value is string => typeof value === 'string' && value.trim().length > 0)
        .join(' ')
        .trim();

    return PROJECT_TARGET_FIELDS.map((field) => ({
        ...field,
        description: methodologyContext ? `${field.description} Methodology context: ${methodologyContext}.` : field.description,
    }));
}

function parseSchemaDocument(row: PolicySchemaRow): Record<string, unknown> | null {
    if (row.document && typeof row.document === 'object') {
        return row.document as Record<string, unknown>;
    }

    if (row.rawSchema && typeof row.rawSchema === 'object') {
        return row.rawSchema as Record<string, unknown>;
    }

    return null;
}

async function getProjectSchemaRow(methodologyBusinessData: unknown, dataSource: DataSource): Promise<PolicySchemaRow | null> {
    const policyTopicId = parsePolicyTopicId(methodologyBusinessData);
    if (!policyTopicId) {
        logger.warn('Unable to resolve policy topic ID from methodology business data.');
        return null;
    }

    const rows = await dataSource.query(
        `SELECT name, description, document, "rawSchema"
         FROM policy_schema
         WHERE "policyTopicId" = $1
         ORDER BY "createdAt" ASC, id ASC`,
        [policyTopicId],
    ) as PolicySchemaRow[];

    if (!rows.length) {
        logger.warn(`No policy_schema rows found for policyTopicId=${policyTopicId}.`);
        return null;
    }

    const projectSchema = rows.find((row) => row.name === 'Project');
    if (!projectSchema) {
        throw new Error(`No policy_schema row named "Project" found for policyTopicId=${policyTopicId}.`);
    }

    return projectSchema;
}

async function getJsonMappingResponse(userMessage: string): Promise<MappingResult[]> {
    const output = await getModelResponse({ systemPrompt: MAPPING_SYSTEM_PROMPT, userMessage });

    try {
        return parseModelOutput(output);
    } catch (firstError) {
        if (!RETRY_INVALID_JSON_WITH_LLM) {
            throw new Error(`Unable to parse model output as JSON and RETRY_INVALID_JSON_WITH_LLM is disabled. Error: ${(firstError as Error).message}.`);
        }

        const jsonRetryOutput = await getModelResponse({
            systemPrompt: 'You convert model responses into strict JSON.',
            userMessage: buildJsonRetryMessage(output),
        });

        try {
            return parseModelOutput(jsonRetryOutput);
        } catch (secondError) {
            throw new Error(`Unable to parse model output as JSON. First error: ${(firstError as Error).message}. Second error: ${(secondError as Error).message}.`);
        }
    }
}

export async function buildProjectFieldMapFromMethodology(
    methodologyBusinessData: unknown,
    dataSource: DataSource,
): Promise<ProjectFieldMap | null> {
    if (!USE_LLM_MAPPING) {
        logger.log('Using heuristic-based field mapping (FIELD_MAPPING_METHOD=heuristic)');
        return buildProjectFieldMapHeuristic(methodologyBusinessData, dataSource);
    }

    // Verify API keys are available for LLM mode
    const hasGeminiKey = !!process.env.GEMINI_API_KEY;
    const hasOpenAiKey = !!process.env.OPENAI_API_KEY;

    if (!hasGeminiKey && !hasOpenAiKey) {
        logger.warn(
            'FIELD_MAPPING_METHOD is set to "llm" but no API keys found (GEMINI_API_KEY or OPENAI_API_KEY). ' +
            'Falling back to heuristic-based mapping.'
        );
        return buildProjectFieldMapHeuristic(methodologyBusinessData, dataSource);
    }

    logger.log('Using LLM-based field mapping (FIELD_MAPPING_METHOD=llm)');
    return buildProjectFieldMapLlm(methodologyBusinessData, dataSource);
}

async function buildProjectFieldMapLlm(
    methodologyBusinessData: unknown,
    dataSource: DataSource,
): Promise<ProjectFieldMap | null> {
    const projectSchema = await getProjectSchemaRow(methodologyBusinessData, dataSource);
    if (!projectSchema) {
        return null;
    }

    const schemaDocument = parseSchemaDocument(projectSchema);
    if (!schemaDocument) {
        logger.warn(`Project schema ${projectSchema.name ?? '<unknown>'} has no usable JSON document.`);
        return null;
    }

    const fieldsData = buildFallbackTargetFields(methodologyBusinessData);
    const { descriptions: leafDescriptions, paths: leafPaths } = await buildSchemaLeafDescriptions(schemaDocument, fieldsData);

    const userMessage = `Here is the input for matching:\n\nFields:\n${JSON.stringify(fieldsData, null, 2)}\n\nLeaf descriptions by index:\n${JSON.stringify(leafDescriptions, null, 2)}\n\nReturn strict JSON only following the required output format.`;

    const mappedFields = await getJsonMappingResponse(userMessage);
    const projectFieldMap: ProjectFieldMap = Object.fromEntries(
        fieldsData.map((field) => [field.fieldName, null]),
    );

    mappedFields.forEach((result) => {
        if (!result.fieldName) {
            return;
        }

        projectFieldMap[result.fieldName] = result.matchedIndex === null
            ? null
            : (leafPaths[result.matchedIndex] ?? null);
    });

    return projectFieldMap;
}

function buildProjectFieldMapHeuristic(
    methodologyBusinessData: unknown,
    _dataSource: DataSource,
): ProjectFieldMap | null {
    const fieldsData = buildFallbackTargetFields(methodologyBusinessData);
    const projectFieldMap: ProjectFieldMap = Object.fromEntries(
        fieldsData.map((field) => [field.fieldName, null]),
    );

    // Simple heuristic: return null for all fields (no mapping)
    // This allows the system to function without LLM dependencies
    logger.debug('Heuristic field mapping: no automatic field mapping performed');
    return projectFieldMap;
}