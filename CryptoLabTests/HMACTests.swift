//
//  HMACTests.swift
//  CryptoLab
//
//  Created by Branko Popovic on 3/30/17.
//  Copyright © 2017 Branko Popovic. All rights reserved.
//

import XCTest
import CryptoLab

class HMACTests: XCTestCase {
	
	fileprivate let testData = "some test data".data(using: .utf8)!
	fileprivate let key = "some test key".data(using: .utf8)!
	
	fileprivate let testBlock1 = "some ".data(using: .utf8)!
	fileprivate let testBlock2 = "test ".data(using: .utf8)!
	fileprivate let testBlock3 = "data".data(using: .utf8)!
	
    override func setUp() {
        super.setUp()
        // Put setup code here. This method is called before the invocation of each test method in the class.
    }
    
	/*
	All correct codes for comparation are generated from http://www.freeformatter.com/hmac-generator.html#ad-output
	*/
	
	func testMD4AuthCode() {
		let correctCode = "2d7dfb54d43d794db1e5237a4b8b0447"
		
		let hmac = HMACAuth(key: key, hashFunction: .md4)
		
		if let code = hmac.authenticationCode(forData: testData) {
			XCTAssert(code.hexEncodedString() == correctCode, "Calculated code does not match")
			return
		}
		XCTAssert(false)
	}
	
	func testMD5AuthCode() {
		let correctCode = "64329bf731e138b0ad7b277293235ff7"
		
		let hmac = HMACAuth(key: key, hashFunction: .md5)
		
		if let code = hmac.authenticationCode(forData: testData) {
			XCTAssert(code.hexEncodedString() == correctCode, "Calculated code does not match")
			return
		}
		XCTAssert(false)
	}
	
	func testSHA1AuthCode() {
		let correctCode = "5d8572908d01140b7c976e2c425f5f91d2e9797a"
		
		let hmac = HMACAuth(key: key, hashFunction: .sha1)
		
		if let code = hmac.authenticationCode(forData: testData) {
			XCTAssert(code.hexEncodedString() == correctCode, "Calculated code does not match")
			return
		}
		XCTAssert(false)
	}
	
	func testSHA224AuthCode() {
		let correctCode = "238628ebd8133d8180aae2015a6072131f35d6a3b14b8bf411d83d82"
		
		let hmac = HMACAuth(key: key, hashFunction: .sha224)
		
		if let code = hmac.authenticationCode(forData: testData) {
			XCTAssert(code.hexEncodedString() == correctCode, "Calculated code does not match")
			return
		}
		XCTAssert(false)
	}
	
	func testSHA256AuthCode() {
		let correctCode = "af5fe68f8633a55beac6a2462b883e6080840c3c857a6e74a3163d6dc0cd26b4"
		
		let hmac = HMACAuth(key: key, hashFunction: .sha256)
		
		if let code = hmac.authenticationCode(forData: testData) {
			XCTAssert(code.hexEncodedString() == correctCode, "Calculated code does not match")
			return
		}
		XCTAssert(false)
	}
	
	func testSHA384AuthCode() {
		let correctCode = "736b806431618f001212a2eb6073ec8e2b62bb8cfdbcf4b9b48f71efe65629fa1bb8e0259f655c579cc98fbf455de438"
		
		let hmac = HMACAuth(key: key, hashFunction: .sha384)
		
		if let code = hmac.authenticationCode(forData: testData) {
			XCTAssert(code.hexEncodedString() == correctCode, "Calculated code does not match")
			return
		}
		XCTAssert(false)
	}
	
	func testSHA512AuthCode() {
		let correctCode = "e6af74f3ded93856843cba84e87a26d50d13dc5753450fdcafc30c19a0aa7ff9fc4743c3dd6732052991429ad080c9e46f20302c8ec76fe75619e8de0daa1092"
		
		let hmac = HMACAuth(key: key, hashFunction: .sha512)
		
		if let code = hmac.authenticationCode(forData: testData) {
			XCTAssert(code.hexEncodedString() == correctCode, "Calculated code does not match")
			return
		}
		XCTAssert(false)
	}
	
	//MARK: Block auth code
	
	func testMD4BlockAuth() {
		let correctCode = "2d7dfb54d43d794db1e5237a4b8b0447"
		
		let hmac = HMACAuth(key: key, hashFunction: .md4)
		
		hmac.update(withData: testBlock1)
		hmac.update(withData: testBlock2)
		hmac.update(withData: testBlock3)
		
		if let code = hmac.finish() {
			XCTAssert(code.hexEncodedString() == correctCode, "Calculated code does not match")
			return
		}
		
		XCTAssert(false)
	}
	
	func testMD5BlockAuth() {
		let correctCode = "64329bf731e138b0ad7b277293235ff7"
		
		let hmac = HMACAuth(key: key, hashFunction: .md5)
		
		hmac.update(withData: testBlock1)
		hmac.update(withData: testBlock2)
		hmac.update(withData: testBlock3)
		
		if let code = hmac.finish() {
			XCTAssert(code.hexEncodedString() == correctCode, "Calculated code does not match")
			return
		}
		
		XCTAssert(false)
	}
	
	func testSHA1BlockAuth() {
		let correctCode = "5d8572908d01140b7c976e2c425f5f91d2e9797a"
		
		let hmac = HMACAuth(key: key, hashFunction: .sha1)
		
		hmac.update(withData: testBlock1)
		hmac.update(withData: testBlock2)
		hmac.update(withData: testBlock3)
		
		if let code = hmac.finish() {
			XCTAssert(code.hexEncodedString() == correctCode, "Calculated code does not match")
			return
		}
		
		XCTAssert(false)
	}
	
	func testSHA224BlockAuth() {
		let correctCode = "238628ebd8133d8180aae2015a6072131f35d6a3b14b8bf411d83d82"
		
		let hmac = HMACAuth(key: key, hashFunction: .sha224)
		
		hmac.update(withData: testBlock1)
		hmac.update(withData: testBlock2)
		hmac.update(withData: testBlock3)
		
		if let code = hmac.finish() {
			XCTAssert(code.hexEncodedString() == correctCode, "Calculated code does not match")
			return
		}
		
		XCTAssert(false)
	}
	
	func testSHA256BlockAuth() {
		let correctCode = "af5fe68f8633a55beac6a2462b883e6080840c3c857a6e74a3163d6dc0cd26b4"
		
		let hmac = HMACAuth(key: key, hashFunction: .sha256)
		
		hmac.update(withData: testBlock1)
		hmac.update(withData: testBlock2)
		hmac.update(withData: testBlock3)
		
		if let code = hmac.finish() {
			XCTAssert(code.hexEncodedString() == correctCode, "Calculated code does not match")
			return
		}
		
		XCTAssert(false)
	}
	
	func testSHA384BlockAuth() {
		let correctCode = "736b806431618f001212a2eb6073ec8e2b62bb8cfdbcf4b9b48f71efe65629fa1bb8e0259f655c579cc98fbf455de438"
		
		let hmac = HMACAuth(key: key, hashFunction: .sha384)
		
		hmac.update(withData: testBlock1)
		hmac.update(withData: testBlock2)
		hmac.update(withData: testBlock3)
		
		if let code = hmac.finish() {
			XCTAssert(code.hexEncodedString() == correctCode, "Calculated code does not match")
			return
		}
		
		XCTAssert(false)
	}
	
	func testSHA512BlockAuth() {
		let correctCode = "e6af74f3ded93856843cba84e87a26d50d13dc5753450fdcafc30c19a0aa7ff9fc4743c3dd6732052991429ad080c9e46f20302c8ec76fe75619e8de0daa1092"
		
		let hmac = HMACAuth(key: key, hashFunction: .sha512)
		
		hmac.update(withData: testBlock1)
		hmac.update(withData: testBlock2)
		hmac.update(withData: testBlock3)
		
		if let code = hmac.finish() {
			XCTAssert(code.hexEncodedString() == correctCode, "Calculated code does not match")
			return
		}
		
		XCTAssert(false)
	}
}
