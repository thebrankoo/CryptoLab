- [CryotoLab](#cryotolab)
	- [Features](#features)
		- [Hash functions](#hash-functions)
		- [Encryption/Decryption](#encryptiondecryption)
		- [Authentication/Key exchange](#authenticationKey-exchange)
	- [Basic Examples](#basic-examples)
		- [MD5](#md5)
		- [AES](#aes)
		- [Blowfish](#blowfish)
		- [RSA](#rsa)
		- [DSA](#dsa)
		- [HMAC](#hmac)
		- [Diffie-Hellman](#diffiehellman)
	- [Contribution](#contribution)

# CryotoLab
Cryptolab is swift wrapper around OpenSSL Crypto toolkit.
To build it change module.modulemap header paths from "/Users/branko/CryptoLab/Frameworks/openssl.framework/Headers/.." to "yourAbsolutePathToCryptoLab/CryptoLab/Frameworks/openssl.framework/Headers/.." and build the framework.

## Features
- Swift implementation
- Intuitive use
- OpenSSL Wrapper
- Data and String extensions
- Supports data block updates

### Hash functions

- md5
- sha1
- sha224
- sha256
- sha384
- sha512

### Encryption/Decryption

- AES
- RSA
- Blowfish

### Authentication/Key exchange

- DSA
- RSA
- HMAC
- Diffie-Hellman

## Basic Examples 

(For more examples check out unit tests.)

### MD5 
```swift
let testData = "Test string".data(using: .utf8)!
let hashFunc = MD5Hash()
let hashCode = hashFunc.hash(data: testData)
```
Or you can use data/string extension.

```swift
let testData = "Test string".data(using: .utf8)!
let hashCodeFromData = testData.md5()
let hashCodeFromString = "Test string".md5()
```

### AES
```swift
do {
	//Data to encrypt, key and initialization vector
	let testData = "test string".data(using: .utf8)
	let key16Byte =	Data(bytes: [0x5f, 0xf5, 0x0c, 0x5b, 0x60, 0x96, 0x84, 0xa2, 0x35, 0xd5, 0xc5, 0xbf, 0x24, 0x69, 0x40, 0x8a])
	let genericIV =	Data(bytes: [0x4f, 0x83, 0x51, 0xae, 0x1c, 0x48, 0xf4, 0x81, 0x65, 0xf8, 0x1b, 0x53, 0x3d, 0xd6, 0xd9, 0x1f])

	//Encryption
	let cryptorEnc = try AESCipher(key: key16Byte, iv: genericIV, blockMode: .cbc)
	let encrypted = try cryptorEnc.encrypt(data: testData)

	//Decryption
	let cryptorDec = try AESCipher(key: key16Byte, iv: genericIV, blockMode: .cbc)
	let decrypted = try cryptorDec.decrypt(data: encrypted)
}
catch let err {
	//handle error
}
```
You can use AES in blocks

```swift
	let block1 = "block1 ".data(using: .utf8)!
	let block2 = "block2 ".data(using: .utf8)!
	let block3 = "block3".data(using: .utf8)!

	do {
		let aes = try AESCipher(key: key32Byte, iv: genericIV, blockMode: .ctr)
		
		try aes.updateEncryption(withDataBlock: block1)
		try aes.updateEncryption(withDataBlock: block2)
		try aes.updateEncryption(withDataBlock: block3)
		let encryptedData = try aes.finishEncryption()
	}
	catch let err {
		//handle error
	}
```

### Blowfish

```swift
	let key	= "secret".data(using: .utf8)!
	let genericIV =	"12345678".data(using: .utf8)!
	let testData = "12345678".data(using: .utf8)!

	let blowfishEnc = BlowfishCipher(key: key, iv: genericIV, encryptionMode: .ecb)
	let blowfishDec = BlowfishCipher(key: key, iv: genericIV, encryptionMode: .ecb)

	do {
		let encrypted = try blowfishEnc.encrypt(data: testData)
		let decrypted = try blowfishDec.decrypt(data: encrypted)
	}
	catch let err {
		//handle error
	}
```

### RSA

```swift
	let testData = Data(bytes: [0x50, 0xb7, 0x73, 0xc8, 0x42, 0x1e, 0x3d, 0x1a, 0x5e, 0xc4, 0x48, 0x50, 0x80, 0x03, 0x03, 0x66])

	let decryptor = RSACipher(padding: .pkcs1)

	guard let pubK = decryptor.publicKey?.data(using: .utf8) else {
		return
	}

	let encryptor = RSACipher(publicKey: pubK, padding: .pkcs1)

	do {
		let encryptedData = try encryptor.encrypt(data: testData)
		let decryptedData = try decryptor.decrypt(data: encryptedData)
	}
	catch let err {
		//handle error
	}
```

Sign/Verify

```swift
	let testData = Data(bytes: [0x50, 0xb7, 0x73, 0xc8, 0x42, 0x1e, 0x3d, 0x1a, 0x5e, 0xc4, 0x48, 0x50, 0x80, 0x03, 0x03, 0x66])

	let signer = RSACipher()
	let signature = signer.sign(data: testData, type: .md5)
	let verify = signer.verify(data: testData, signature: signature!, type: .md5)

```

### DSA

```swift
	let dsa = DSAAuth()
	let signature = dsa.sign(data: toSign)! 
	let verified = dsa.verify(signature: signature, digest: toSign)
```

### HMAC

```swift
	let testData = "some test data".data(using: .utf8)!
	let key = "some test key".data(using: .utf8)!

	let hmac = HMACAuth(key: key, hashFunction: .md5)

	let code = hmac.authenticationCode(forData: testData) 
```
Or you can use data/string extension

```swift
	let codeFromData = testData.hmacAuthCode(withKey: key, hashFunction: .md5)
	let codeFromString = "some test string".hmacAuthCode(withKey: key, hashFunction: .md5)
```

### Diffie-Hellman

```swift
	let dhClient1 = DiffieHellman(primeLength: 512)
	let dhClient2 = DiffieHellman(p: dhClient1.p!, g: dhClient1.g!)

	//shared secrets are the same
	let sharedSecret1 = dhClient1.computeSharedSecret(withPublicKey: dhClient2.publicKey!.data(using: .utf8)!)
	let sharedSecret2 = dhClient2.computeSharedSecret(withPublicKey: dhClient1.publicKey!.data(using: .utf8)!)
```

## Contribution 

Any kind of contribution is more than welcome (bug reporting, bug fixing, new feature implementation etc.).

- Open new github issue for feature/bug you are working on or pick the existing one
- Fork the repository
- Do your magic
- Do a proper documentation and cover basic unit tests
- Submit a pull request when done
