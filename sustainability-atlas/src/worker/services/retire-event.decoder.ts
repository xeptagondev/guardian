/**
 * Decoder for Guardian's on-chain retirement event.
 *
 * Guardian's RETIRE contract emits, per executed retirement:
 *
 *   Retire(address account, RetireTokenRequest[] tokens)
 *   struct RetireTokenRequest { address token; int64 count; int64[] serials; }
 *
 * `count` carries the amount for fungible tokens; `serials` carries the exact
 * serial numbers for non-fungible ones. Some events populate both, so callers
 * must pick by the token's actual type rather than by which field is non-zero.
 *
 * Only RETIRE_EXECUTED_TOPIC is a retirement. The contract emits a
 * byte-identical payload for the *request* half of the approval flow, and those
 * requests are not always executed — verified against Mirror Node, where the
 * executed signature's serials matched nft_cache.deleted 1053/1053 while the
 * request signature named serials that were never actually deleted. Counting
 * both would over-report retirement.
 */

/** topic0 of the executed `Retire` event — the only signature that counts. */
export const RETIRE_EXECUTED_TOPIC =
    '0x760b5d447de9a6afab4457b996807616ccd3b048f15f77e82cc55fdb70962f4e';

/** Guards against a malformed or unrelated payload steering the decoder into a
 *  huge allocation; no real retirement comes close to these. */
const MAX_TOKENS_PER_EVENT = 64;
const MAX_SERIALS_PER_TOKEN = 100_000;

export interface RetiredToken {
    /** Hedera token ID, converted from the EVM address in the log. */
    tokenId: string;
    /** Fungible amount, in the token's smallest units. Zero for non-fungible. */
    count: number;
    /** Non-fungible serials. Empty for fungible. */
    serials: number[];
}

export interface RetireEvent {
    /** Hedera account ID that performed the retirement. */
    accountId: string;
    tokens: RetiredToken[];
}

/** Splits ABI-encoded hex into 32-byte words. */
function toWords(data: string): bigint[] {
    const hex = (data ?? '').replace(/^0x/, '');
    const out: bigint[] = [];
    for (let i = 0; i + 64 <= hex.length; i += 64) {
        out.push(BigInt(`0x${hex.slice(i, i + 64)}`));
    }
    return out;
}

/** Byte offsets in the ABI encoding are relative to a base and always a
 *  multiple of 32; anything else means this isn't the payload we expect. */
function wordOffset(value: bigint, base: number, limit: number): number | null {
    const bytes = Number(value);
    if (!Number.isSafeInteger(bytes) || bytes < 0 || bytes % 32 !== 0) {
        return null;
    }
    const index = base + bytes / 32;
    return index < limit ? index : null;
}

/**
 * Decodes a `Retire` log's data field. Returns null when the payload isn't the
 * expected shape — the retire contracts also emit ownership and admin events
 * whose data is a bare word, and those must be ignored rather than guessed at.
 *
 * Fixed word offsets are deliberately NOT used: `RetireTokenRequest[]` is a
 * dynamic array of dynamic structs, so a multi-token retirement lays out
 * differently from a single-token one. Reading it positionally produced
 * nonsense token IDs and absurd counts on real multi-token events.
 */
export function decodeRetireEvent(data: string): RetireEvent | null {
    const w = toWords(data);
    if (w.length < 4) {
        return null;
    }

    const arrayAt = wordOffset(w[1], 0, w.length);
    if (arrayAt === null) {
        return null;
    }

    const tokenCount = Number(w[arrayAt]);
    if (!Number.isSafeInteger(tokenCount) || tokenCount < 1 || tokenCount > MAX_TOKENS_PER_EVENT) {
        return null;
    }
    // Element offsets are relative to the first word after the array length.
    const elementBase = arrayAt + 1;
    if (elementBase + tokenCount > w.length) {
        return null;
    }

    const tokens: RetiredToken[] = [];
    for (let i = 0; i < tokenCount; i++) {
        const elementAt = wordOffset(w[elementBase + i], elementBase, w.length);
        if (elementAt === null || elementAt + 2 >= w.length) {
            return null;
        }

        const serialsAt = wordOffset(w[elementAt + 2], elementAt, w.length);
        if (serialsAt === null) {
            return null;
        }

        const serialCount = Number(w[serialsAt]);
        if (!Number.isSafeInteger(serialCount) || serialCount < 0 || serialCount > MAX_SERIALS_PER_TOKEN) {
            return null;
        }
        if (serialsAt + serialCount >= w.length + 1 && serialCount > 0) {
            return null;
        }

        const serials: number[] = [];
        for (let s = 0; s < serialCount; s++) {
            serials.push(Number(w[serialsAt + 1 + s]));
        }

        tokens.push({
            tokenId: `0.0.${w[elementAt]}`,
            count: Number(w[elementAt + 1]),
            serials,
        });
    }

    return { accountId: `0.0.${w[0]}`, tokens };
}
