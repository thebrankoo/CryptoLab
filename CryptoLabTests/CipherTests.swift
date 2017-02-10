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
    
	func testExample() {
		let result = GeneralCipher().testCipher()
		print("AES Test \(result.hexEncodedString())")
	}
		
}

//extension Data {
//	func hexEncodedString() -> String {
//		return map { String(format: "%02hhx", $0) }.joined()
//	}
//}
