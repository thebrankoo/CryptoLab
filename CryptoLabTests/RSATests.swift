//
//  RSATests.swift
//  CryptoLab
//
//  Created by Branko Popovic on 3/18/17.
//  Copyright © 2017 Branko Popovic. All rights reserved.
//

import XCTest
import CryptoLab

class RSATests: XCTestCase {
	
	let testData = Data(bytes: [0x50, 0xb7, 0x73, 0xc8, 0x42, 0x1e, 0x3d, 0x1a, 0x5e, 0xc4, 0x48, 0x50, 0x80, 0x03, 0x03, 0x66])
	
    override func setUp() {
        super.setUp()
    }
	
	//MARK: Encryption/Decryption
	
	func testRSA_PKCS1() {
		let decryptor = RSACipher(padding: .pkcs1)
		
		guard let pubK = decryptor.publicKey?.data(using: .utf8) else {
			XCTFail("RSA Can't get public key")
			return
		}
		
		let encryptor = RSACipher(publicKey: pubK, padding: .pkcs1)
		
		do {
			let encryptedData = try encryptor.encrypt(data: testData)
			let decryptedData = try decryptor.decrypt(data: encryptedData)
			XCTAssert(testData == decryptedData, "RSA original data and decrypted data don't match")
		}
		catch let err {
			XCTFail("RSA Error: \(err)")
		}
	}
	
	func testRSA_OAEP() {
		let decryptor = RSACipher(padding: .pkcs1_oaep)
		
		guard let pubK = decryptor.publicKey?.data(using: .utf8) else {
			XCTFail("RSA Can't get public key")
			return
		}
		
		let encryptor = RSACipher(publicKey: pubK, padding: .pkcs1_oaep)
		
		do {
			let encryptedData = try encryptor.encrypt(data: testData)
			let decryptedData = try decryptor.decrypt(data: encryptedData)
			XCTAssert(testData == decryptedData, "RSA original data and decrypted data don't match")
		}
		catch let err {
			XCTFail("RSA Error: \(err)")
		}
	}
	
	//MARK: Sign/Verify
	
	func testRSASignVerifyMD5() {
		let signer = RSASignature(type: .md5)
		
		let signature = signer.sign(data: testData)
		let verify = signer.verify(data: testData, signature: signature!)
		
		XCTAssert(verify, "")
	}
	
	func testRSASignVerifySHA1() {
		let signer = RSASignature(type: .sha1)
		
		let signature = signer.sign(data: testData)
		let verify = signer.verify(data: testData, signature: signature!)
		
		XCTAssert(verify)
	}
	
	func testRSASignVerifyRIPEMD160() {
		let signer = RSASignature(type: .ripemd160)
		
		let signature = signer.sign(data: testData)
		let verify = signer.verify(data: testData, signature: signature!)
		
		XCTAssert(verify)
	}
}
