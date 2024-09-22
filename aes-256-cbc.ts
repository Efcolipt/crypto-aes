
  /**
   * Generates a random string of a given size
   */
const generateRandomIV = (size: number): Buffer => {
  const bits = (size + 1) * 6;
  const buffer = randomBytes(Math.ceil(bits / 8));

  return Buffer.from(buffer.toString('base64').slice(0, size))
}

export class Aes256CBC {
  /**
   * The key for signing and encrypting values. It is derived
   * from the user provided secret.
   */
  #cryptoKey: Buffer;

    /**
   * Use `dot` as a separator for joining encrypted value, iv and the
   * hmac hash. The idea is borrowed from JWTs.
   */
   #separator = '.';

  constructor(key: string | Buffer) {
    this.#cryptoKey = createHash('sha256').update(key).digest();
  }

  /**
   * The algorithm in use
   */
  get algorithm(): string {
    return 'aes-256-cbc';
  }

  /**
   * Encrypt a given piece of value using the app secret. A wide range of
   * data types are supported.
   *
   * - String
   * - Arrays
   * - Objects
   * - Booleans
   * - Numbers
   * - Dates
   *
   * You can optionally define a purpose for which the value was encrypted and
   * mentioning a different purpose/no purpose during decrypt will fail.
   */
  encrypt(message: unknown): string {
    /**
     * Using a random string as the iv for generating unpredictable values
     */
    const iv = generateRandomIV(16);

    /**
     * Creating cipher
     */
    const cipher = createCipheriv(this.algorithm, this.#cryptoKey, iv);

    /**
     * Encoding value to a string so that we can set it on the cipher
     */
    const encodedValue = JSON.stringify({ message });

    /**
     * Set final to the cipher instance and encrypt it
     */
    const encrypted = Buffer.concat([
      cipher.update(encodedValue, 'utf-8'),
      cipher.final(),
    ]);

    /**
     * Concatenate `encrypted value` and `iv` by urlEncoding them. The concatenation is required
     * to generate the HMAC, so that HMAC checks for integrity of both the `encrypted value`
     * and the `iv`.
     */
    const result = `${BufferUrlBase64.urlEncode(encrypted)}${
      this.#separator
    }${BufferUrlBase64.urlEncode(iv)}`;

    /**
     * Returns the result + hmac
     */
    return `${result}${this.#separator}${new Hmac(this.#cryptoKey).generate(
      result
    )}`;
  }

  /**
   * Decrypt value and verify it against a purpose
   */
  decrypt<T>(value: string): T | null {
    if (typeof value !== 'string') {
      return null;
    }

    /**
     * Make sure the encrypted value is in correct format. ie
     * [encrypted value].[iv].[hash]
     */
    const [encryptedEncoded, ivEncoded, hash] = value.split(this.#separator);
    if (!encryptedEncoded || !ivEncoded || !hash) {
      return null;
    }

    /**
     * Make sure we are able to urlDecode the encrypted value
     */
    const encrypted = BufferUrlBase64.urlDecode(encryptedEncoded, 'base64');
    if (!encrypted) {
      return null;
    }

    /**
     * Make sure we are able to urlDecode the iv
     */
    const iv = BufferUrlBase64.urlDecode(ivEncoded);
    if (!iv) {
      return null;
    }

    /**
     * Make sure the hash is correct, it means the first 2 parts of the
     * string are not tampered.
     */
    const isValidHmac = new Hmac(this.#cryptoKey).compare(
      `${encryptedEncoded}${this.#separator}${ivEncoded}`,
      hash
    );

    if (!isValidHmac) {
      return null;
    }

    /**
     * The Decipher can raise exceptions with malformed input, so we wrap it
     * to avoid leaking sensitive information
     */
    try {
      const decipher = createDecipheriv(this.algorithm, this.#cryptoKey, iv);
      const decrypted =
        decipher.update(encrypted, 'base64', 'utf8') + decipher.final('utf8');
      const data: {message: T} = JSON.parse(decrypted)
      return data.message;
    } catch {
      return null;
    }
  }
}

