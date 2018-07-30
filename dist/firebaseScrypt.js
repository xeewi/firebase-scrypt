'use strict';

Object.defineProperty(exports, "__esModule", {
  value: true
});
exports.FirebaseScrypt = undefined;

var _promise = require('babel-runtime/core-js/promise');

var _promise2 = _interopRequireDefault(_promise);

var _child_process = require('child_process');

function _interopRequireDefault(obj) { return obj && obj.__esModule ? obj : { default: obj }; }

class FirebaseScrypt {
  /**
   * init - Init module
   * @param {object} firebaseHashConfig Hash config from firebase
   * @param {number} firebaseHashConfig.memCost Memory cost
   * @param {number} firebaseHashConfig.rounds Hash rounds
   * @param {string} firebaseHashConfig.saltSeparator Salt separator
   * @param {string} firebaseHashConfig.signerKey Signer key
   * @returns {FirebaseScrypt} FirebaseScrypt object
   */
  static init(firebaseHashConfig) {
    return new FirebaseScrypt(firebaseHashConfig);
  }

  constructor({ memCost, rounds, saltSeparator, signerKey }) {
    this.memCost = memCost;
    this.rounds = rounds;
    this.saltSeparator = saltSeparator;
    this.signerKey = signerKey;
  }

  /**
   * hash - Hash password
   * @param {string} password Password string
   * @param {string} salt Password salt
   * @returns {string} Password hash
   */
  hash(password, salt) {
    return new _promise2.default((resolve, reject) => {
      (0, _child_process.exec)(`echo "${password}" | ../scrypt/scrypt "${this.signerKey}" "${salt}" "${this.saltSeparator}" "${this.rounds}" "${this.memCost}" -P`, (error, stdout) => error ? reject(error) : resolve(stdout));
    });
  }

  /**
   * verify - Verify if password is equal to hash
   * @param {string} password Password string to verify
   * @param {string} salt Password salt to verify
   * @param {string} hash Password hash
   * @returns {boolean} isValid
   */
  verify(password, salt, hash) {
    return this.hash(password, salt).then(generatedHash => generatedHash === hash);
  }
}
exports.FirebaseScrypt = FirebaseScrypt;