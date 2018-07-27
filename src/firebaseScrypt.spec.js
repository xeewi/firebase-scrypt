import { FirebaseScrypt } from './firebaseScrypt'

const firebaseConfigMock = {
  memCost: 1,
  rounds: 1,
  saltSeparator: 'separator',
  signerKey: 'superlongkey',
}

const scrypt = FirebaseScrypt.init(firebaseConfigMock)

describe('FirebaseScrypt', () => {
  describe('Initialisation', () => {
    test('Should return a FirebaseScrypt Object', () => {
      expect(scrypt instanceof FirebaseScrypt).toBe(true)
    })

    test('Should set configuration', () => {
      expect(scrypt.memCost).toBe(firebaseConfigMock.memCost)
      expect(scrypt.signerKey).toBe(firebaseConfigMock.signerKey)
      expect(scrypt.rounds).toBe(firebaseConfigMock.rounds)
      expect(scrypt.saltSeparator).toBe(firebaseConfigMock.saltSeparator)
    })
  })
})
