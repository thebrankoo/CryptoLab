# CryotoLab
Cryptolab is swift wrapper around OpenSSL Crypto toolkit.

## Features
- SYMMETRIC CIPHERS
- PUBLIC KEY CRYPTOGRAPHY AND KEY AGREEMENT
- AUTHENTICATION CODES, HASH FUNCTIONS

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

### AES
```swift
do {
let testData = "test string".data(using: .utf8)
var key16Byte		=			Data(bytes: [0x5f, 0xf5, 0x0c, 0x5b, 0x60, 0x96, 0x84, 0xa2, 0x35, 0xd5, 0xc5, 0xbf, 0x24, 0x69, 0x40, 0x8a])
var genericIV		=			Data(bytes: [0x4f, 0x83, 0x51, 0xae, 0x1c, 0x48, 0xf4, 0x81, 0x65, 0xf8, 0x1b, 0x53, 0x3d, 0xd6, 0xd9, 0x1f])

var cryptorEnc = try AESCipher(key: key16Byte, iv: genericIV, blockMode: .cbc)
let encrypted = try cryptorEnc.encrypt(data: testData)

var cryptorDec = try AESCipher(key: key16Byte, iv: genericIV, blockMode: .cbc)
let decrypted = try cryptorDec.decrypt(data: encrypted)

XCTAssert(testData == decrypted, "AES Failed: Decrypted data is not the same as data that is encrypted")
}
catch let err {
XCTAssert(false, "AES Test Error: \(err)")
}
```
