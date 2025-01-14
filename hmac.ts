import { createHmac } from 'crypto';
import { BufferUrlBase64 } from './buffer-url-base64';

export class Hmac {
  #key: Buffer;

  constructor(key: Buffer) {
    this.#key = key;
  }

  /**
   * Generate the hmac
   */
  generate(value: string): string {
    const hmac = createHmac('sha256', this.#key).update(value).digest();

    return BufferUrlBase64.urlEncode(hmac);
  }

  /**
   * Compare raw value against an existing hmac
   */
  compare(value: string, existingHmac: string): boolean {
    return this.generate(value) === existingHmac;
  }
}
