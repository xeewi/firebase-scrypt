declare module "firebase-scrypt" {
  type Base64String = string;

  export interface FirebaseScryptOptions {
    memCost: number;
    rounds: number;
    saltSeparator: Base64String;
    signerKey: Base64String;
  }

  export class FirebaseScrypt {
    constructor(options: FirebaseScryptOptions);

    hash(password: string, salt: Base64String): Promise<Base64String>;

    verify(password: string, salt: Base64String, hashedPassword: Base64String): Promise<boolean>;
  }
}
