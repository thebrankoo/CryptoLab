//
//  DSA.swift
//  CryptoLab
//
//  Created by Branko Popovic on 3/7/17.
//  Copyright © 2017 Branko Popovic. All rights reserved.
//

import Foundation
import OpenSSL

/**
DSA sign/verify class
*/
public class DSAAuth: NSObject, SignVerifier {
	
	public var signVerifier: CoreSignVerifier
	
	/**
	DSA private key (fetch only)
	*/
	public var privateKey: String? {
		return (signVerifier as? DSACore)?.extractPrivateKey()
	}
	
	/**
	DSA public key (fetch only)
	*/
	public var publicKey: String? {
		return (signVerifier as? DSACore)?.extractPublicKey()
	}
	
	/**
	Creates new DSA Object and generates key pair.
	*/
	public override init() {
		signVerifier = DSACore()
		super.init()
	}
	
	/**
	Creates new DSA Object with public key.
	
	- parameter publicKey: Custom public key
	*/
	public init(publicKey: Data) {
		signVerifier = DSACore(publicKey: publicKey)
		super.init()
	}
	
	/**
	Creates new DSA Object with public and private key.
	
	- parameter publicKey: Custom public key
	- parameter privateKey: Custom private key
	*/
	public init(publicKey: Data, privateKey: Data) {
		signVerifier = DSACore(publicKey: publicKey, privateKey: privateKey)
		super.init()
	}
}
