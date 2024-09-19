import {
  Cipher,
  createCipheriv,
  createDecipheriv,
  createHash,
  createHmac,
  Decipher,
  Hmac,
  randomBytes,
} from 'crypto';

class AES {
  /*
    IV поколение
    Для некоторых алгоритмов шифрования IV ( Initialization Vector ) должны быть случайными, как в случае AES-CBC, 
    а для других они должны быть уникальными, как в случае AES-CTR, AES-GCM или ChaCha20. 
    Их также называют «nonce», когда желаемым свойством является уникальность, а не IV.
  */

  /* 
   Symmetric key of 32 bytes shared between Alice and Bob
    const key: Buffer = Buffer.from('4b00c9504d4b76bd913ecd27df90305fa3201e0e15e4e61023782ad0867660de', 'hex') 
    Message encoded as a Buffer
    const message: Buffer = Buffer.from('Your password is:Se@ld-i5-great', 'utf8')

    Message encrypted by Alice
    const encryptedMessage = encrypt(message, key)
    console.log(encryptedMessage.toString('hex')
    > 144c57a662562f474212b72c2a5765d4a882ffd3459adb1bb07e48fc62d2f3db68618a9e4d61022ddb29e36c22039fb7

    console.log(decrypt(encryptedMessage, key).toString('utf8'))
    > Your password is:Se@ld-i5-great
  */

  /* 
    Правильный способ шифрования с помощью AES-CBC — добавить то, что известно как Код аутентификации сообщения, 
    который обеспечивает целостность зашифрованного сообщения. MAC — это своего рода контрольная сумма, 
    вычисляемая для сообщения с помощью общего секретного ключа. 
    Если этот MAC не соответствует расшифровке, сообщение было изменено до прибытия
  */

  /* 
    Если злоумышленник знает первые 16 байтов сообщения (в нашем примере разумно предположить, 
    что Your password is это префикс перед всеми сообщениями этого типа), он может внедрить выбранные блоки ( g0 и g1)
  */

  /*
    пример во многом вдохновлен вполне реальной уязвимостью под названием efail.de, 
    которая существует в почтовых клиентах, расшифровывающих письма S/MIME или PGP
  */

  static aes256CbcEncrypt(message: string, key: Buffer, keyMac: Buffer): string {
    const enc = Buffer.from(message, "base64");

    const iv = randomBytes(16)

    const cipher: Cipher = createCipheriv('aes-256-cbc', key, iv)

    const encryptedData = Buffer.concat([iv, cipher.update(enc), cipher.final()])

    const hmac: Hmac = createHmac('sha256', keyMac)

    hmac.update(encryptedData)

    return Buffer.concat([encryptedData, hmac.digest()]).toString('base64')
  }

  static aes256CbcDecrypt(message: string, key: Buffer, keyMac: Buffer): string {
    const enc = Buffer.from(message, "base64");

    const payload: Buffer = enc.subarray(0, -32) // we retrieve the MAC at the end

    const mac: Buffer = enc.subarray(-32)

    const hmac: Hmac = createHmac('sha256', keyMac)

    hmac.update(payload)

    const mac2 = hmac.digest()

    if (!mac.equals(mac2)) throw new Error('MAC invalid')

    const iv: Buffer = payload.subarray(0, 16)

    const cipherText: Buffer = payload.subarray(16)

    const decipher: Decipher = createDecipheriv('aes-256-cbc', key, iv)

    return Buffer.concat([decipher.update(cipherText), decipher.final()]).toString('utf-8')
  }

  /*
    Кроме того, деталь, которую иногда упускают из виду в AES-CTR, — одноразовый номер должен быть разным 
    для каждого 16-байтового блока, а не для каждого вызова. 
    Если сообщение превышает 16 байт, AES-CTR использует одноразовый номер как счетчик (отсюда и название «CTR» для COUNTER) 
    и увеличивает его для каждого блока AES. Разработчик, подсчитывающий вызовы AES-CTR, а не блоки AES, 
    неосознанно повторно использовал бы одноразовые номера, как только сообщения превысят 16 байт
  */

  /* 
  
    невозможно зашифровать более 64 ГБ данных с помощью AES-GCM: AES-GCM использует 4-байтовый счетчик для 
    генерации одноразовых кодов для AES-CTR, поэтому он не может зашифровать более 4 миллиардов блоков (2^32), т. е. 64 ГБ.
  
  */


  static aes256CtrEncrypt(nonce: Buffer, message: string, keyEnc: Buffer): string {
    const enc = Buffer.from(message, "base64");

    const cipher: Cipher = createCipheriv('aes-256-ctr', keyEnc, nonce)

    return Buffer.concat([nonce, cipher.update(enc), cipher.final()]).toString('base64')
  }

  static aes256CtrDecrypt(message: string, keyEnc: Buffer): string {
    const enc = Buffer.from(message, "base64");

    const iv = enc.subarray(0, 16)

    const cipherText = enc.subarray(16)

    const decipher: Decipher = createDecipheriv('aes-256-ctr', keyEnc, iv)

    return Buffer.concat([decipher.update(cipherText), decipher.final()]).toString('utf8')
  }


  static aes256GcmEncrypt(message: string, key: Buffer): string {
    const iv = randomBytes(12);

    const cipher = createCipheriv('aes-256-gcm', key, iv);

    const enc1 = cipher.update(message, 'utf8');

    const enc2 = cipher.final();

    return Buffer.concat([enc1, enc2, iv, cipher.getAuthTag()]).toString('base64');
  }

  static aes256GcmDecrypt(encryptedData: string, key: Buffer): string {
    let enc = Buffer.from(encryptedData, "base64");

    const iv = enc.subarray(enc.length - 28, enc.length - 16);

    const tag = enc.subarray(enc.length - 16);

    enc = enc.subarray(0, enc.length - 28);

    const decipher = createDecipheriv('aes-256-gcm', key, iv);

    decipher.setAuthTag(tag);

    let str = decipher.update(enc, null, 'utf8');

    str += decipher.final('utf8');

    return str;
  }

}
