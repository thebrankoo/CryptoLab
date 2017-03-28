//
//  BlowfishTests.swift
//  CryptoLab
//
//  Created by Branko Popovic on 3/20/17.
//  Copyright © 2017 Branko Popovic. All rights reserved.
//

import XCTest
import CryptoLab

class BlowfishTests: XCTestCase {
	
	var key			=		"secret".data(using: .utf8)!//Data(bytes: [0x5f, 0xf5, 0x0c, 0x5b, 0x60, 0x96, 0x84, 0xa2, 0x35, 0xd5, 0xc5, 0xbf, 0x24, 0x69, 0x40, 0x8a, 0x5f, 0xf5, 0x0c, 0x5b, 0x60, 0x96, 0x84, 0xa2, 0x35, 0xd5, 0xc5, 0xbf, 0x24, 0x69, 0x40, 0x8a])
	var genericIV	=		"12345678".data(using: .utf8)!//Data(bytes: [0x8f, 0xfc, 0xc9, 0xd6, 0xdd, 0xf9, 0xca, 0x4c])  //Data(bytes: [0x4f, 0x83, 0x51, 0xae, 0x1c, 0x48, 0xf4, 0x81])// 0x65, 0xf8, 0x1b, 0x53, 0x3d, 0xd6, 0xd9, 0x1f])
	var testData	=		"12345678".data(using: .utf8)! //Data(bytes: [0xeb, 0xf9, 0x91, 0x42, 0x6a, 0x3f, 0x1b, 0x5f])//, 0x5d, 0x7e, 0x4e, 0xa1, 0x35, 0xe2, 0xe5, 0x01, 0x27, 0xe7, 0x5d, 0x8f, 0x41, 0xbb, 0x09, 0x9b, 0xb7, 0x98, 0x5c, 0x2a, 0x99, 0x33, 0x8a, 0x8a])
	
    override func setUp() {
        super.setUp()
    }
	
	func testBlowfishECB(){
		let blowfishEnc = BlowfishCipher(key: key, iv: genericIV, encryptionMode: .ecb)
		let blowfishDec = BlowfishCipher(key: key, iv: genericIV, encryptionMode: .ecb)
		
		do {
			let encrypted = try blowfishEnc.encrypt(data: testData)
			let decrypted = try blowfishDec.decrypt(data: encrypted)
			XCTAssert(testData == decrypted, "Blowfish decrypted data is not the same as test data")
		}
		catch let err {
			XCTFail("Blowfish Error: \(err)")
		}
	}
	
	func testBlowfishCBC(){
		let encIVEC = "12345678".data(using: .utf8)!
		let decIVEC = "12345678".data(using: .utf8)!
		
		let blowfishEnc = BlowfishCipher(key: key, iv: encIVEC, encryptionMode: .cbc)
		let blowfishDec = BlowfishCipher(key: key, iv: decIVEC, encryptionMode: .cbc)
		
		do {
			let encrypted = try blowfishEnc.encrypt(data: testData)
			
			let decrypted = try blowfishDec.decrypt(data: encrypted)
			
			XCTAssert(testData == decrypted, "Blowfish decrypted data is not the same as test data")
		}
		catch let err {
			XCTFail("Blowfish Error: \(err)")
		}
	}
	
	func testBlowfishCFB64(){
		let encIVEC = "12345678".data(using: .utf8)!
		let decIVEC = "12345678".data(using: .utf8)!
		
		let blowfishEnc = BlowfishCipher(key: key, iv: encIVEC, encryptionMode: .cfb64)
		let blowfishDec = BlowfishCipher(key: key, iv: decIVEC, encryptionMode: .cfb64)
		
		do {
			let encrypted = try blowfishEnc.encrypt(data: testData)
			let decrypted = try blowfishDec.decrypt(data: encrypted)
			
			XCTAssert(testData == decrypted, "Blowfish decrypted data is not the same as test data")
		}
		catch let err {
			XCTFail("Blowfish Error: \(err)")
		}
	}
	
	func testBlowfishOFB64(){
		let encIVEC = "12345678".data(using: .utf8)!
		let decIVEC = "12345678".data(using: .utf8)!
		
		let blowfishEnc = BlowfishCipher(key: key, iv: encIVEC, encryptionMode: .ofb64)
		let blowfishDec = BlowfishCipher(key: key, iv: decIVEC, encryptionMode: .ofb64)
		
		do {
			let encrypted = try blowfishEnc.encrypt(data: testData)
			let decrypted = try blowfishDec.decrypt(data: encrypted)
			
			XCTAssert(testData == decrypted, "Blowfish decrypted data is not the same as test data")
		}
		catch let err {
			XCTFail("Blowfish Error: \(err)")
		}
	}
}
