import { fromBuffer } from 'file-type';

/**
 * Best-guess Content-Type for a buffer of unknown origin (e.g. raw IPFS
 * content, which carries no Content-Type of its own). Pinned to
 * file-type@16.5.4 — the last release published with CommonJS support,
 * matching this project's CommonJS build (17+ is ESM-only).
 */
export async function sniffMime(buffer: Buffer): Promise<string> {
    const result = await fromBuffer(buffer);
    return result?.mime ?? 'application/octet-stream';
}
