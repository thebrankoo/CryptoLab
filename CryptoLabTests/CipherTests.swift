//
//  CipherTests.swift
//  CryptoLab
//
//  Created by Branko Popovic on 2/9/17.
//  Copyright © 2017 Branko Popovic. All rights reserved.
//

import XCTest
import CryptoLab

class CipherTests: XCTestCase {
    
    override func setUp() {
        super.setUp()
        // Put setup code here. This method is called before the invocation of each test method in the class.
    }
    
    override func tearDown() {
        // Put teardown code here. This method is called after the invocation of each test method in the class.
        super.tearDown()
    }
	
	func testBlowfish() {
		let bf = BlowfishCoreCipher(key: "neki key proizvoljni".data(using: .utf8)!)
		let data = bf.ecbEncrypt(data: "1234567891011".data(using: .utf8)!)
		let decData = bf.ecbDecrypt(data: data)
		
		print("BF \(data.hexEncodedString())")
		print("BF Dec \(String(data: decData, encoding: .utf8))")
		
	}
	
	func testExample() {
		let keyArray = [UInt8]([0x4e, 0x72, 0xac, 0x09, 0xbc, 0x65, 0x6e, 0x4c, 0xf3, 0xe2, 0xea, 0x61, 0x0e, 0x57, 0x7f, 0xee,	0x47, 0x6d, 0x29, 0x88, 0x7f, 0x61, 0x1e, 0xe0])
		let keyData = Data(bytes: keyArray)
		let ivData = Data(bytes: keyArray)
		
		do {
			let aesEnc = try AESCipher(key: keyData, iv: ivData, blockMode: .cbc)
			
			do {
				let result = try aesEnc.encrypt(data: "Neki test".data(using: .utf8)!)
				let aesDec = try aesEnc.decrypt(data: result)
				print("AES Test \(result.hexEncodedString())")
				print("AES Dec \(String(data: aesDec, encoding: .utf8))")
			}
			catch let error {
				print("AES Enc \(error)")
				XCTAssert(false)
			}
		}
		catch let error {
			print("AES Init \(error)")
			XCTAssert(false)
		}
		
	}
	
	func testRSA() {
		let testString = "test string"
		let rsa = RSACipher(padding: .sslv23)
		
		if let ecrypt = rsa.encrypt(data: testString.data(using: .utf8)!) {
			if let decrypt = rsa.decrypt(data: ecrypt) {
				XCTAssert(testString.data(using: .utf8)! == decrypt)
				return
			}
		}
		
		XCTAssert(false)
	}
		
}

//extension Data {
//	func hexEncodedString() -> String {
//		return map { String(format: "%02hhx", $0) }.joined()
//	}
//}
