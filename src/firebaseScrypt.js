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
}
