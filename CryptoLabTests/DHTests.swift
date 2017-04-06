//
//  DHTests.swift
//  CryptoLab
//
//  Created by Branko Popovic on 4/3/17.
//  Copyright © 2017 Branko Popovic. All rights reserved.
//

import XCTest
import CryptoLab

class DHTests: XCTestCase {
        
    override func setUp() {
        super.setUp()
	}
	
	func testDHPrimeLen512() {
		let dh1 = DiffieHellman(primeLength: 512)
		
		let dh2 = DiffieHellman(p: dh1.p!, g: dh1.g!)
		
		if let secret1 = dh1.computeSharedSecret(withPublicKey: dh2.publicKey!.data(using: .utf8)!) {
			if let secret2 = dh2.computeSharedSecret(withPublicKey: dh1.publicKey!.data(using: .utf8)!) {
				XCTAssert(secret1 == secret2, "Shared secret should be the same")
				return
			}
		}
		XCTAssert(false)
	}
	
	func testDHPrimeLen1024() {
		let dh1 = DiffieHellman(primeLength: 1024)
		
		let dh2 = DiffieHellman(p: dh1.p!, g: dh1.g!)
		
		if let secret1 = dh1.computeSharedSecret(withPublicKey: dh2.publicKey!.data(using: .utf8)!) {
			if let secret2 = dh2.computeSharedSecret(withPublicKey: dh1.publicKey!.data(using: .utf8)!) {
				XCTAssert(secret1 == secret2, "Shared secret should be the same")
				return
			}
		}
		XCTAssert(false)
	}
	
	func testDHPrimeLen2048() {
		let dh1 = DiffieHellman(primeLength: 2048)
		
		let dh2 = DiffieHellman(p: dh1.p!, g: dh1.g!)
		
		if let secret1 = dh1.computeSharedSecret(withPublicKey: dh2.publicKey!.data(using: .utf8)!) {
			if let secret2 = dh2.computeSharedSecret(withPublicKey: dh1.publicKey!.data(using: .utf8)!) {
				XCTAssert(secret1 == secret2, "Shared secret should be the same")
				return
			}
		}
		XCTAssert(false)
	}
	
	func testDHFail() {
		let dh1 = DiffieHellman(primeLength: 512)
		let falseDH = DiffieHellman(primeLength: 512)
		
		let dh2 = DiffieHellman(p: falseDH.p!, g: dh1.g!)
		
		if let secret1 = dh1.computeSharedSecret(withPublicKey: dh2.publicKey!.data(using: .utf8)!) {
			if let secret2 = dh2.computeSharedSecret(withPublicKey: dh1.publicKey!.data(using: .utf8)!) {
				XCTAssert(secret1 != secret2, "Shared secret should be different")
				return
			}
		}
		XCTAssert(false)
	}

}
