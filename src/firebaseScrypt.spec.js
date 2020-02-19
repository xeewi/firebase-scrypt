import { FirebaseScrypt } from './firebaseScrypt'

const firebaseConfigMock = {
  memCost: 1,
  rounds: 1,
  saltSeparator: 'separator',
  signerKey: 'superlongkey',
}
const passwordMock = 'test'
const saltMock = 'salt'
const hashMock = 'PrZI5nfqjOEk'

const scrypt = new FirebaseScrypt(firebaseConfigMock)

describe('FirebaseScrypt', () => {
  describe('Initialisation', () => {
    test('Should return a FirebaseScrypt Object', () => {
      expect(scrypt).toBeInstanceOf(FirebaseScrypt)
    })

    test('Should set configuration', () => {
      expect(scrypt.memCost).toBe(firebaseConfigMock.memCost)
      expect(scrypt.signerKey).toBe(firebaseConfigMock.signerKey)
      expect(scrypt.rounds).toBe(firebaseConfigMock.rounds)
      expect(scrypt.saltSeparator).toBe(firebaseConfigMock.saltSeparator)
    })
  })

  describe('Functions', () => {
    test('Hash password', () => scrypt.hash(passwordMock, saltMock)
      .then(hash => expect(hash).toBe(hashMock)))

    test('Verify hash', () => scrypt.verify(passwordMock, saltMock, hashMock)
      .then(isValid => expect(isValid).toBe(true)))

    test('Verify hash mismatch (wrong password)', () => scrypt.verify('wrong mock', saltMock, hashMock)
      .then(isValid => expect(isValid).toBe(false)))

    test('Verify hash mismatch (wrong hash length)', () => scrypt.verify(passwordMock, saltMock, 'YQ==')
      .then(isValid => expect(isValid).toBe(false)))
  })
})
