//
//  DSATests.swift
//  CryptoLab
//
//  Created by Branko Popovic on 3/30/17.
//  Copyright © 2017 Branko Popovic. All rights reserved.
//

import XCTest
import CryptoLab

class DSATests: XCTestCase {
	
	let toSign = "some data to sign".data(using: .utf8)!
	
    override func setUp() {
        super.setUp()
        // Put setup code here. This method is called before the invocation of each test method in the class.
    }
	
	func testBasicDSA() {
		let dsa = DSAAuth()
		if let signature = dsa.sign(data: toSign) {
			let verified = dsa.verify(data: toSign, signature: signature)
			XCTAssert(verified)
			return
		}
		XCTAssert(false)
	}
	
	func testPublicKeyVerify() {
		let dsaSigner = DSAAuth()
		
		if let publicKey = dsaSigner.publicKey?.data(using: .utf8) {
			let dsaVerifier = DSAAuth(publicKey: publicKey)
			if let signature = dsaSigner.sign(data: toSign) {
				let verified = dsaVerifier.verify(data: toSign, signature: signature)
				XCTAssert(verified)
				return
			}
		}
		XCTAssert(false)
	}
	
	func testCustomKeys() {
		let privateKey = "-----BEGIN DSA PRIVATE KEY-----\nMIIBuwIBAAKBgQC/NI+FOkTbpcFggzx1fPMKbHch03GgmF/wwfgVwDSVNrQFK+pl\n7RwvtKJY91J0poyxI2ywopoXurzkvbDZzcaNjpcrBcuqOOK9oIg5C51N0PwpzANb\nE8btsA0fgc9J7FkLee61RgdqdxYrCYIPO29EN2fhhSECWh0TnKdBB4+yOQIVAO3z\nzhiGehIitPz4blOqPkqko7WNAoGBAJm8sESxsKWzlioBU2oBes64JCze7X5JELC1\n7qQgdoLk/zNF4fsA8yQtGSBb9XKqyvy00BXYNX2dycq5Hv41rXOjUlr0xCLG0WGn\n1hDYHgXbW0ChW7oxtRce9fXT8fNEcKW8uLi5O3ua93LItQeWVEx0Grd8tHB7mFLP\n/j2xS2TyAoGAeLk5iVsfHkvgOk2H6hlNKjIrng4Mj0Dsgbq0zyVFwb7SJMvvvx2w\ntcG6NiT4DAs9KTWh0wT37RSwy85WwaG7Wu5YPGQQog9bmxXFAHdjgZ87ViVk+TJF\nv5+2pzofe2mBSIP7nU8AsSVRC57hQskN7vVG2rgN/hiOQKXupOV9AGECFBUjeo3c\nfcWewasrP4Qiq5c4pZIH\n-----END DSA PRIVATE KEY-----\n"
		
		let publicKey = "-----BEGIN PUBLIC KEY-----\nMIIBtzCCASwGByqGSM44BAEwggEfAoGBAL80j4U6RNulwWCDPHV88wpsdyHTcaCY\nX/DB+BXANJU2tAUr6mXtHC+0olj3UnSmjLEjbLCimhe6vOS9sNnNxo2OlysFy6o4\n4r2giDkLnU3Q/CnMA1sTxu2wDR+Bz0nsWQt57rVGB2p3FisJgg87b0Q3Z+GFIQJa\nHROcp0EHj7I5AhUA7fPOGIZ6EiK0/PhuU6o+SqSjtY0CgYEAmbywRLGwpbOWKgFT\nagF6zrgkLN7tfkkQsLXupCB2guT/M0Xh+wDzJC0ZIFv1cqrK/LTQFdg1fZ3Jyrke\n/jWtc6NSWvTEIsbRYafWENgeBdtbQKFbujG1Fx719dPx80Rwpby4uLk7e5r3csi1\nB5ZUTHQat3y0cHuYUs/+PbFLZPIDgYQAAoGAeLk5iVsfHkvgOk2H6hlNKjIrng4M\nj0Dsgbq0zyVFwb7SJMvvvx2wtcG6NiT4DAs9KTWh0wT37RSwy85WwaG7Wu5YPGQQ\nog9bmxXFAHdjgZ87ViVk+TJFv5+2pzofe2mBSIP7nU8AsSVRC57hQskN7vVG2rgN\n/hiOQKXupOV9AGE=\n-----END PUBLIC KEY-----\n"
		
		let dsa = DSAAuth(publicKey: publicKey.data(using: .utf8)!, privateKey: privateKey.data(using: .utf8)!)
		
		if let signature = dsa.sign(data: toSign) {
			let verified = dsa.verify(data: toSign, signature: signature)
			XCTAssert(verified)
			return
		}
		XCTAssert(false)
	}
    
}
