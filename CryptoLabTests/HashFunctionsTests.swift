//
//  HashFunctionsTests.swift
//  CryptoLab
//
//  Created by Branko Popovic on 2/4/17.
//  Copyright © 2017 Branko Popovic. All rights reserved.
//

import XCTest
import CryptoLab

class HashFunctionsTests: XCTestCase {
    
 fileprivate let defaultTestString = "Test string"
	
	override func setUp() {
		super.setUp()
		// Put setup code here. This method is called before the invocation of each test method in the class.
	}
	
	override func tearDown() {
		super.tearDown()
	}
	
	//MARK: Testing hashing function correctness
	//Comparation results were obtained from: http://www.sha1-online.com/ if not specified differently
	
	func testMD5Correctness() {
		let correctString = "0fd3dbec9730101bff92acc820befc34"
		
		let testData = defaultTestString.data(using: .utf8)!
		let hashFunc = MD5Hash()
		
		let hashString = hashFunc.hash(data: testData).hexEncodedString()
		
		XCTAssert(hashString == correctString, "MD5 hash result is not correct")
		
	}
	
	func testSHA1Correctness() {
		let correctString = "18af819125b70879d36378431c4e8d9bfa6a2599"
		
		let testData = defaultTestString.data(using: .utf8)!
		let hashFunc = SHA1Hash()
		
		let hashString = hashFunc.hash(data: testData).hexEncodedString()
		
		XCTAssert(hashString == correctString, "SHA1 hash result is not correct")
		
	}
	
	//Comparation results obtained from: http://www.miniwebtool.com/sha224-hash-generator/
	func testSHA224Correctness() {
		let correctString = "425433d1ec90fd9957c43c7b3372c3ad2c08378d3480a962a4244671"
		
		let testData = defaultTestString.data(using: .utf8)!
		let hashFunc = SHA224Hash()
		
		let hashString = hashFunc.hash(data: testData).hexEncodedString()
		
		XCTAssert(hashString == correctString, "SHA224 hash result is not correct")
		
	}
	
	func testSHA256Correctness() {
		let correctString = "a3e49d843df13c2e2a7786f6ecd7e0d184f45d718d1ac1a8a63e570466e489dd"
		
		let testData = defaultTestString.data(using: .utf8)!
		let hashFunc = SHA256Hash()
		
		let hashString = hashFunc.hash(data: testData).hexEncodedString()
		
		XCTAssert(hashString == correctString, "SHA224 hash result is not correct")
		
	}
	
	func testSHA384Correctness() {
		let correctString = "83ca14ebf3005a10f50839742bda82aa607d972a03b1e6a3086e29195ceaf05f038fecdff02aff6e9dcdd273268875f7"
		
		let testData = defaultTestString.data(using: .utf8)!
		let hashFunc = SHA384Hash()
		
		let hashString = hashFunc.hash(data: testData).hexEncodedString()
		
		XCTAssert(hashString == correctString, "SHA224 hash result is not correct")
		
	}
	
	func testSHA512Correctness() {
		let correctString = "811aa0c53c0039b6ead0ca878b096eed1d39ed873fd2d2d270abfb9ca620d3ed561c565d6dbd1114c323d38e3f59c00df475451fc9b30074f2abda3529df2fa7"
		
		let testData = defaultTestString.data(using: .utf8)!
		let hashFunc = SHA512Hash()
		
		let hashString = hashFunc.hash(data: testData).hexEncodedString()
		
		XCTAssert(hashString == correctString, "SHA224 hash result is not correct")
		
	}
}

extension Data {
	func hexEncodedString() -> String {
		return map { String(format: "%02hhx", $0) }.joined()
	}
}
