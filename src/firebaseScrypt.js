import { createCipheriv, scrypt, timingSafeEqual } from 'crypto'

const ALGORITHM = 'aes-256-ctr'

// Should match block length (16 bytes for AES)
const IV_LENGTH = 16

// Should match algorithm (AES 256 = 256 bits = 32 bytes
const KEYLEN = 256 / 8

/**
 * base64decode - Decodes a base64 encoded string into a Buffer
 *
 * The hashes exported via the firebase CLI's auth:export command use the
 * standard base64 alphabet with + and / being used in addition to the 62
 * alphanumeric characters.
 *
 * The hashes exported via the Admin SDK's
 * listUsers command use the URL safe base64 alphabet which uses - and _
 * instead.
 *
 * This function allows this library to be compatible with hashes in either
 * format.
 *
 * @param {string} encoded Base64 encoded string
 * @returns {Buffer} decoded
 */
function base64decode (encoded) {
  return Buffer.from(encoded.replace(/-/g, '+').replace(/_/g, '/'), 'base64')
}

/**
 * From https://github.com/firebase/scrypt/issues/2#issuecomment-548203625
 * 1. Decrypt the User's salt, and Project's base64_signer_key and
 *    base64_salt_separator from base64
 *
 * 2. Run crypto.scrypt function with the parameters:
 *    password = User's password
 *    salt = User's salt + salt_separator
 *    options.N = 2 ^ mem_cost
 *    options.r = rounds
 *    options.p = 1
 *
 * 3. Then take the returned derived Key, and run AES on it, with the key being
 *    the derived key, and the input being the project's signer_key (decrypted
 *    from base64)
 *
 * 4. Encode the result using base64
 */
export class FirebaseScrypt {
  constructor ({ memCost, rounds, saltSeparator, signerKey }) {
    this.memCost = memCost
    this.rounds = rounds
    this.saltSeparator = saltSeparator
    this.signerKey = signerKey
  }

  /**
   * hash - Hash password
   * @param {string} password Password string
   * @param {string} salt Password salt
   * @returns {string} Password hash
   */
  hash (password, salt) {
    return new Promise((resolve, reject) => {
      const bSalt = Buffer.concat([
        base64decode(salt),
        base64decode(this.saltSeparator),
      ])
      const iv = Buffer.alloc(IV_LENGTH, 0)

      scrypt(password, bSalt, KEYLEN, {
        N: 2 ** this.memCost,
        r: this.rounds,
        p: 1,
      }, (err, derivedKey) => {
        if (err) {
          return reject(err)
        }

        try {
          const cipher = createCipheriv(ALGORITHM, derivedKey, iv)
          resolve(Buffer.concat([ cipher.update(base64decode(this.signerKey)), cipher.final() ]).toString('base64'))
        } catch (error) {
          reject(error)
        }
      })
    })
  }

  /**
   * verify - Verify if password is equal to hash
   * @param {string} password Password string to verify
   * @param {string} salt Password salt to verify
   * @param {string} hash Password hash
   * @returns {boolean} isValid
   */
  verify (password, salt, hash) {
    return this.hash(password, salt).then(generatedHash => {
      const knownHash = base64decode(hash)
      const bGeneratedHash = base64decode(generatedHash)
      if (bGeneratedHash.length !== knownHash.length) {
        // timingSafeEqual throws when buffer lengths don't match
        timingSafeEqual(knownHash, knownHash)
        return false
      }

      return timingSafeEqual(bGeneratedHash, knownHash)
    })
  }
}
