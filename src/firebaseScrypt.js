import { exec } from 'child_process'

export class FirebaseScrypt {
  static init (firebaseHashConfig) {
    return new FirebaseScrypt(firebaseHashConfig)
  }

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
      exec(
        `echo "${password}" | ../scrypt/scrypt "${this.signerKey}" "${salt}" "${this.saltSeparator}" "${this.rounds}" "${this.memCost}" -P`,
        (error, stdout) => error ? reject(error) : resolve(stdout),
      )
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
    return this.hash(password, salt)
      .then(generatedHash => generatedHash === hash)
  }
}
