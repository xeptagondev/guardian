import { describe, expect, it } from '@jest/globals';
import { sniffMime } from '@shared/utils/mime-sniff';

describe('sniffMime', () => {
    it('detects a PNG from its magic bytes', async () => {
        // A real (1x1 transparent pixel) PNG — file-type reads past the raw
        // signature into the IHDR chunk, so a truncated/fake signature isn't enough.
        const png = Buffer.from(
            'iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mNk+A8AAQUBAScY42YAAAAASUVORK5CYII=',
            'base64',
        );
        expect(await sniffMime(png)).toBe('image/png');
    });

    it('detects a ZIP from its magic bytes', async () => {
        const zip = Buffer.from([0x50, 0x4b, 0x03, 0x04, 0, 0, 0, 0]);
        expect(await sniffMime(zip)).toBe('application/zip');
    });

    it('falls back to application/octet-stream for unrecognized bytes', async () => {
        const unknown = Buffer.from('{"just":"json text, no magic bytes"}');
        expect(await sniffMime(unknown)).toBe('application/octet-stream');
    });
});
