# CryotoLab
Cryptolab is swift wrapper around OpenSSL Crypto toolkit.

## Features
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

## Basics

### MD5 
```swift
let testData = "Test string".data(using: .utf8)!
let hashFunc = MD5Hash()
let hashCode = hashFunc.hash(data: testData)
```
Or you can use data extension.

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
}
```
