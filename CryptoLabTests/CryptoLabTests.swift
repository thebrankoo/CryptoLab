//
//  CryptoLabTests.swift
//  CryptoLabTests
//
//  Created by Branko Popovic on 2/1/17.
//  Copyright © 2017 Branko Popovic. All rights reserved.
//

import XCTest
import CryptoLab

class CryptoLabTests: XCTestCase {
	
	fileprivate let defaultTestString = "Test string"
	
    override func setUp() {
        super.setUp()
        // Put setup code here. This method is called before the invocation of each test method in the class.
    }
	
    override func tearDown() {
        super.tearDown()
    }
	
	//MARK: Testing deterministic property of hashing functions
	
    func testMD5Deterministic() {
		let testData = defaultTestString.data(using: .utf8)!
		let hashFunc = MD5Hash()
		
		let hashA = hashFunc.hash(data: testData)
		let hashB = hashFunc.hash(data: testData)
		
		XCTAssert(hashA == hashB, "MD5 hash not deterministic!")
    }
	
	func testSHA1Deterministic() {
		let testData = defaultTestString.data(using: .utf8)!
		let hashFunc = SHA1Hash()
		
		let hashA = hashFunc.hash(data: testData)
		let hashB = hashFunc.hash(data: testData)
		
		XCTAssert(hashA == hashB, "SHA1 hash not deterministic!")
	}
	
	//MARK: Testing hashing function correctness
	//Comparation results were obtained from: http://www.sha1-online.com/
	
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
}

extension Data {
	func hexEncodedString() -> String {
		return map { String(format: "%02hhx", $0) }.joined()
	}
}
