// Turn bytes fetched from a page into something safe to render.
//
// SECURITY: the source bytes are attacker-controlled — any site can serve
// whatever it likes at its favicon URL. We never store or render them. They are
// decoded into an ImageBitmap and re-drawn at a fixed size, so the stored PNG
// carries only pixels: no SVG script, no EXIF, no trailing payload. A blob that
// fails to decode is dropped.
import { uint8ArrayToBase64 } from '../utils/base64';
import { PNG_DATA_URL_PREFIX } from './store';
import { logger } from '../utils/logger';

// Raster formats createImageBitmap can decode. SVG is excluded on purpose: it
// is a script container and is not decodable in a worker anyway.
const ALLOWED_TYPES = new Set([
  'image/png',
  'image/jpeg',
  'image/webp',
  'image/gif',
  'image/x-icon',
  'image/vnd.microsoft.icon',
]);

const MAX_SOURCE_BYTES = 128 * 1024;

// Refuse oversized source images rather than decoding them into memory.
const MAX_SOURCE_PIXELS = 1024;

const ICON_PIXELS = 32;

export function isAllowedIconType(mimeType: string): boolean {
  return ALLOWED_TYPES.has(mimeType.split(';')[0].trim().toLowerCase());
}

export function isWithinSourceLimit(byteLength: number): boolean {
  return byteLength > 0 && byteLength <= MAX_SOURCE_BYTES;
}

/**
 * Re-encode arbitrary image bytes as a 32x32 PNG data URL, or null if they are
 * not an image we accept.
 */
export async function normalizeIcon(bytes: Uint8Array, mimeType: string): Promise<string | null> {
  if (!isAllowedIconType(mimeType) || !isWithinSourceLimit(bytes.byteLength)) {
    return null;
  }

  let bitmap: ImageBitmap | null = null;
  try {
    // slice() detaches the view from any larger buffer so Blob gets exactly
    // the icon bytes.
    const blob = new Blob([bytes.slice().buffer as ArrayBuffer], { type: mimeType });
    bitmap = await createImageBitmap(blob);
    if (
      bitmap.width < 1 ||
      bitmap.height < 1 ||
      bitmap.width > MAX_SOURCE_PIXELS ||
      bitmap.height > MAX_SOURCE_PIXELS
    ) {
      return null;
    }

    const canvas = new OffscreenCanvas(ICON_PIXELS, ICON_PIXELS);
    const ctx = canvas.getContext('2d');
    if (!ctx) {
      return null;
    }
    ctx.drawImage(bitmap, 0, 0, ICON_PIXELS, ICON_PIXELS);

    const png = await canvas.convertToBlob({ type: 'image/png' });
    const encoded = uint8ArrayToBase64(new Uint8Array(await png.arrayBuffer()));

    return PNG_DATA_URL_PREFIX + encoded;
  } catch (error) {
    logger.debug('Site icon did not decode', error);
    return null;
  } finally {
    bitmap?.close();
  }
}
