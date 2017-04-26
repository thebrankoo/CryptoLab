//
//  AuthExtensions.swift
//  CryptoLab
//
//  Created by Branko Popovic on 3/13/17.
//  Copyright © 2017 Branko Popovic. All rights reserved.
//

import Foundation

/**
CryptoLab Data extensions
*/
extension Data {
	/**
	Generates HMAC auth code form data
	
	- parameter key: Auth code generation key
	- parameter hasFunction: Auth code generation hash funcion
	
	- returns: Generated HMAC auth code
	*/
	public func hmacAuthCode(withKey key: Data, hashFunction: AuthHashFunction) -> Data? {
		let hmac = HMACAuth(key: key, hashFunction: hashFunction)
		let authData = hmac.authenticationCode(forData: self)
		return authData
	}
	
	/**
	DSA signature of data
	
	- parameter pubK: Public key
	- parameter privK: Private key
	
	- returns: Generated DSA signature of data
	*/
	public func dsaSign(publicKey pubK: Data, privateKey privK: Data) -> Data? {
		let dsa = DSAAuth(publicKey: pubK, privateKey: privK)
		let dsaSigned = dsa.sign(data: self)
		return dsaSigned
	}
	
	/**
	DSA public key verification of data with signature
	
	- parameter signature: DSA generated signature
	- parameter pubK: Public key
	
	- returns: Bool that indicates if verification passed
	*/
	public func dsaVerify(withSignature signature: Data, publicKey pubK: Data) -> Bool {
		let dsa = DSAAuth(publicKey: pubK)
		let verify = dsa.verify(data: self, signature: signature)
		return verify
	}
}

/**
CryptoLab String extensions
*/
extension String {
	/**
	Generates HMAC auth code form string
	
	- parameter key: Auth code generation key
	- parameter hasFunction: Auth code generation hash funcion
	
	- returns: Generated HMAC auth code
	*/
	public func hmacAuthCode(withKey key: Data, hashFunction: AuthHashFunction) -> Data? {
		if let data = self.data(using: .utf8) {
			return data.hmacAuthCode(withKey: key, hashFunction: hashFunction)
		}
		return nil
	}
	
	/**
	DSA signature of string
	
	- parameter pubK: Public key
	- parameter privK: Private key
	
	- returns: Generated DSA signature of string
	*/
	public func dsaSign(publicKey pubK: Data, privateKey privK: Data) -> Data? {
		if let data = self.data(using: .utf8) {
			return data.dsaSign(publicKey: pubK, privateKey: privK)
		}
		return nil
	}
	
	/**
	DSA public key verification of string with signature
	
	- parameter signature: DSA generated signature
	- parameter pubK: Public key
	
	- returns: Bool that indicates if verification passed
	*/
	public func dsaVerify(withSignature signature: Data, publicKey pubK: Data) -> Bool {
		if let data = self.data(using: .utf8) {
			return data.dsaVerify(withSignature: signature, publicKey: pubK)
		}
		return false
	}
}
