//
//  CrypterTests.swift
//  CryptoLab
//
//  Created by Branko Popovic on 3/17/17.
//  Copyright © 2017 Branko Popovic. All rights reserved.
//

import XCTest
import CryptoLab

class AESTests: XCTestCase {
	let testString = "test string"
	var testData: Data!
	var cryptorEnc: Cryptor!
	var cryptorDec: Cryptor!
	
	var key16Byte		=			Data(bytes: [0x5f, 0xf5, 0x0c, 0x5b, 0x60, 0x96, 0x84, 0xa2, 0x35, 0xd5, 0xc5, 0xbf, 0x24, 0x69, 0x40, 0x8a])
	var key24Byte		=			Data(bytes: [0x84, 0x20, 0x72, 0xa3, 0x17, 0x8b, 0x4f, 0xc0, 0xb5, 0x49, 0x78, 0x12, 0x44, 0x46, 0xf8, 0x94, 0x84, 0xde, 0x30, 0xb3, 0x7f, 0x1a, 0xc6, 0x1e])
	var key32Byte		=			Data(bytes: [0xeb, 0xf9, 0x91, 0x42, 0x6a, 0x3f, 0x1b, 0x5f, 0x5d, 0x7e, 0x4e, 0xa1, 0x35, 0xe2, 0xe5, 0x01, 0x27, 0xe7, 0x5d, 0x8f, 0x41, 0xbb, 0x09, 0x9b, 0xb7, 0x98, 0x5c, 0x2a, 0x99, 0x33, 0x8a, 0x8a])
	
	var genericIV		=			Data(bytes: [0x4f, 0x83, 0x51, 0xae, 0x1c, 0x48, 0xf4, 0x81, 0x65, 0xf8, 0x1b, 0x53, 0x3d, 0xd6, 0xd9, 0x1f])
	
	let test16ByteData	=			Data(bytes: [0xf1, 0x48, 0x3a, 0x13, 0x7a, 0x00, 0x6e, 0x99, 0x35, 0xd5, 0xc5, 0xbf, 0x24, 0x69, 0x40, 0x8a])
	let test8ByteData	=			Data(bytes: [0xf1, 0x48, 0x3a, 0x13, 0x7a, 0x00, 0x6e, 0x99])
	let test1ByteData	=			Data(bytes: [0xf1])
	
    override func setUp() {
        super.setUp()
		testData = testString.data(using: .utf8)
    }
	
	//MARK: AES CBC

	func testAES_CBC_128() {
		do {
			cryptorEnc = try AESCipher(key: key16Byte, iv: genericIV, blockMode: .cbc)
			let encrypted = try cryptorEnc.encrypt(data: testData)
			
			cryptorDec = try AESCipher(key: key16Byte, iv: genericIV, blockMode: .cbc)
			let decrypted = try cryptorDec.decrypt(data: encrypted)
			
			XCTAssert(testData == decrypted, "AES Failed: Decrypted data is not the same as data that is encrypted")
		}
		catch let err {
			XCTAssert(false, "AES Test Error: \(err)")
		}
	}
	
	func testAES_CBC_192() {
		do {
			cryptorEnc = try AESCipher(key: key24Byte, iv: genericIV, blockMode: .cbc)
			let encrypted = try cryptorEnc.encrypt(data: testData)
			
			cryptorDec = try AESCipher(key: key24Byte, iv: genericIV, blockMode: .cbc)
			let decrypted = try cryptorDec.decrypt(data: encrypted)
			
			XCTAssert(testData == decrypted, "AES Failed: Decrypted data is not the same as data that is encrypted")
		}
		catch let err {
			XCTAssert(false, "AES Test Error: \(err)")
		}
	}
	
	func testAESCBC_CBC_256() {
		do {
			cryptorEnc = try AESCipher(key: key32Byte, iv: genericIV, blockMode: .cbc)
			let encrypted = try cryptorEnc.encrypt(data: testData)
			
			cryptorDec = try AESCipher(key: key32Byte, iv: genericIV, blockMode: .cbc)
			let decrypted = try cryptorDec.decrypt(data: encrypted)
			
			XCTAssert(testData == decrypted, "AES Failed: Decrypted data is not the same as data that is encrypted")
		}
		catch let err {
			XCTAssert(false, "AES Test Error: \(err)")
		}
	}
	
	//MARK: AES ECB
	
	func testAES_ECB_128() {
		do {
			cryptorEnc = try AESCipher(key: key16Byte, iv: genericIV, blockMode: .ecb)
			let encrypted = try cryptorEnc.encrypt(data: test8ByteData)
			
			cryptorDec = try AESCipher(key: key16Byte, iv: genericIV, blockMode: .ecb)
			let decrypted = try cryptorDec.decrypt(data: encrypted)

			XCTAssert(test8ByteData == decrypted, "AES Failed: Decrypted data is not the same as data that is encrypted")
		}
		catch let err {
			XCTAssert(false, "AES Test Error: \(err)")
		}
	}
	
	func testAES_ECB_192() {
		do {
			cryptorEnc = try AESCipher(key: key24Byte, iv: genericIV, blockMode: .ecb)
			let encrypted = try cryptorEnc.encrypt(data: testData)
			
			cryptorDec = try AESCipher(key: key24Byte, iv: genericIV, blockMode: .ecb)
			let decrypted = try cryptorDec.decrypt(data: encrypted)
			
			XCTAssert(testData == decrypted, "AES Failed: Decrypted data is not the same as data that is encrypted")
		}
		catch let err {
			XCTAssert(false, "AES Test Error: \(err)")
		}
	}
	
	func testAES_ECB_256() {
		do {
			cryptorEnc = try AESCipher(key: key32Byte, iv: genericIV, blockMode: .ecb)
			let encrypted = try cryptorEnc.encrypt(data: testData)
			
			cryptorDec = try AESCipher(key: key32Byte, iv: genericIV, blockMode: .ecb)
			let decrypted = try cryptorDec.decrypt(data: encrypted)
			
			XCTAssert(testData == decrypted, "AES Failed: Decrypted data is not the same as data that is encrypted")
		}
		catch let err {
			XCTAssert(false, "AES Test Error: \(err)")
		}
	}
	
	//MARK: AES CFB
	
	func testAES_CFB_128() {
		do {
			
			let encIV = Data(bytes: [0x4f, 0x83, 0x51, 0xae, 0x1c, 0x48, 0xf4, 0x81, 0x65, 0xf8, 0x1b, 0x53, 0x3d, 0xd6, 0xd9, 0x1f])
			let decIV = Data(bytes: [0x4f, 0x83, 0x51, 0xae, 0x1c, 0x48, 0xf4, 0x81, 0x65, 0xf8, 0x1b, 0x53, 0x3d, 0xd6, 0xd9, 0x1f])
			let toEnc = "1234567813".data(using: .utf8)!
			
			let enc = try AESCipher(key: key16Byte, iv: encIV, blockMode: .cfb)
			let dec = try AESCipher(key: key16Byte, iv: decIV, blockMode: .cfb)
			
			let encrypted = try enc.encrypt(data: toEnc)
			
			
			let decrypted = try dec.decrypt(data: encrypted)
			
			XCTAssert(toEnc == decrypted, "AES Failed: Decrypted data is not the same as data that is encrypted")
		}
		catch let err {
			XCTAssert(false, "AES Test Error: \(err)")
		}
	}
	
	func testAES_CFB_192() {
		do {
			cryptorEnc = try AESCipher(key: key24Byte, iv: genericIV, blockMode: .cfb)
			let encrypted = try cryptorEnc.encrypt(data: testData)
			
			cryptorDec = try AESCipher(key: key24Byte, iv: genericIV, blockMode: .cfb)
			let decrypted = try cryptorDec.decrypt(data: encrypted)
			
			XCTAssert(testData == decrypted, "AES Failed: Decrypted data is not the same as data that is encrypted")
		}
		catch let err {
			XCTAssert(false, "AES Test Error: \(err)")
		}
	}
	
	func testAES_CFB_256() {
		do {
			cryptorEnc = try AESCipher(key: key32Byte, iv: genericIV, blockMode: .cfb)
			let encrypted = try cryptorEnc.encrypt(data: testData)
			
			cryptorDec = try AESCipher(key: key32Byte, iv: genericIV, blockMode: .cfb)
			let decrypted = try cryptorDec.decrypt(data: encrypted)
			
			XCTAssert(testData == decrypted, "AES Failed: Decrypted data is not the same as data that is encrypted")
		}
		catch let err {
			XCTAssert(false, "AES Test Error: \(err)")
		}
	}
	
	//MARK: AES OFB
	
	func testAES_OFB_128() {
		do {
			cryptorEnc = try AESCipher(key: key16Byte, iv: genericIV, blockMode: .ofb)
			let encrypted = try cryptorEnc.encrypt(data: testData)
			
			cryptorDec = try AESCipher(key: key16Byte, iv: genericIV, blockMode: .ofb)
			let decrypted = try cryptorDec.decrypt(data: encrypted)
			
			XCTAssert(testData == decrypted, "AES Failed: Decrypted data is not the same as data that is encrypted")
		}
		catch let err {
			XCTAssert(false, "AES Test Error: \(err)")
		}
	}
	
	func testAES_OFB_192() {
		do {
			cryptorEnc = try AESCipher(key: key24Byte, iv: genericIV, blockMode: .ofb)
			let encrypted = try cryptorEnc.encrypt(data: testData)
			
			cryptorDec = try AESCipher(key: key24Byte, iv: genericIV, blockMode: .ofb)
			let decrypted = try cryptorDec.decrypt(data: encrypted)
			
			XCTAssert(testData == decrypted, "AES Failed: Decrypted data is not the same as data that is encrypted")
		}
		catch let err {
			XCTAssert(false, "AES Test Error: \(err)")
		}
	}
	
	func testAES_OFB_256() {
		do {
			cryptorEnc = try AESCipher(key: key32Byte, iv: genericIV, blockMode: .ofb)
			let encrypted = try cryptorEnc.encrypt(data: testData)
			
			cryptorDec = try AESCipher(key: key32Byte, iv: genericIV, blockMode: .ofb)
			let decrypted = try cryptorDec.decrypt(data: encrypted)
			
			XCTAssert(testData == decrypted, "AES Failed: Decrypted data is not the same as data that is encrypted")
		}
		catch let err {
			XCTAssert(false, "AES Test Error: \(err)")
		}
	}
	
	//MARK: AES CTR
	
	func testAES_CTR_128() {
		do {
			cryptorEnc = try AESCipher(key: key16Byte, iv: genericIV, blockMode: .ctr)
			let encrypted = try cryptorEnc.encrypt(data: testData)
			
			cryptorDec = try AESCipher(key: key16Byte, iv: genericIV, blockMode: .ctr)
			let decrypted = try cryptorDec.decrypt(data: encrypted)
			
			XCTAssert(testData == decrypted, "AES Failed: Decrypted data is not the same as data that is encrypted")
		}
		catch let err {
			XCTAssert(false, "AES Test Error: \(err)")
		}
	}
	
	func testAES_CTR_192() {
		do {
			cryptorEnc = try AESCipher(key: key24Byte, iv: genericIV, blockMode: .ctr)
			let encrypted = try cryptorEnc.encrypt(data: testData)
			
			cryptorDec = try AESCipher(key: key24Byte, iv: genericIV, blockMode: .ctr)
			let decrypted = try cryptorDec.decrypt(data: encrypted)
			
			XCTAssert(testData == decrypted, "AES Failed: Decrypted data is not the same as data that is encrypted")
		}
		catch let err {
			XCTAssert(false, "AES Test Error: \(err)")
		}
	}
	
	func testAES_CTR_256() {
		do {
			cryptorEnc = try AESCipher(key: key32Byte, iv: genericIV, blockMode: .ctr)
			let encrypted = try cryptorEnc.encrypt(data: testData)
			
			cryptorDec = try AESCipher(key: key32Byte, iv: genericIV, blockMode: .ctr)
			let decrypted = try cryptorDec.decrypt(data: encrypted)
			
			XCTAssert(testData == decrypted, "AES Failed: Decrypted data is not the same as data that is encrypted")
		}
		catch let err {
			XCTAssert(false, "AES Test Error: \(err)")
		}
	}

}
