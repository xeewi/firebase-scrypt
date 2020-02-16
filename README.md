# Node Firebase Scrypt

NodeJs implementation of Firebase's Scrypt modified version

## Warning

This module work only with users exported with Firebase Tools CLI and the command `auth:export`. Others way to gets users (Admin SDK, etc.) will give you an incompatible hash.

## Table of Contents

- [Install](#install)
- [Usage](#usage)
  - [Initialisation](#initialisation)
  - [Hash](#hash)
  - [Verify](#verify)
- [Test](#test)

## Install

To install, run : 

`npm i firebase-scrypt`

## Usage

## Firebase parameters

Go to Firebase to get your hash parameters.
To access these parameters, navigate to the 'Users' tab of the 'Authentication' section in the Firebase Console and select 'Password Hash Parameters' from the drop down in the upper-right hand corner of the users table.

### Initialisation

```javascript
import { FirebaseScrypt } from 'firebase-scrypt'

const firebaseParameter = {
  memCost: 1, // replace by your
  rounds: 1, // replace by your
  saltSeparator: 'your-separator', // replace by your 
  signerKey: 'your-key', // replace by your
}

const scrypt = new FirebaseScrypt(firebaseParameters)

```

### Hash

```javascript

[...]

const password = "test"
const salt = "salt"

scrypt.hash(password, salt)
  .then(hash => console.log(hash))

```

### Verify

```javascript

[...]

const password = "test"
const salt = "salt"
const hash = "PrZI5nfqjOEk"

scrypt.verify(password, salt, hash)
  .then(isValid => isValid ? console.log('Valid !') : console.log('Not valid !'))

```

## Test

To test, run : 

`npm run test`
