//
//  AuthExtensions.swift
//  CryptoLab
//
//  Created by Branko Popovic on 3/13/17.
//  Copyright © 2017 Branko Popovic. All rights reserved.
//

import Foundation

extension Data {
	public func hmacAuthCode(withKey key: Data, hashFunction: AuthHashFunction) -> Data? {
		let hmac = HMACAuth(key: key, hashFunction: hashFunction)
		let authData = hmac.authenticationCode(forData: self)
		return authData
	}
	
	public func dsaSign(publicKey pubK: Data, privateKey privK: Data) -> Data? {
		let dsa = DSAAuth(publicKey: pubK, privateKey: privK)
		let dsaSigned = dsa.sign(data: self)
		return dsaSigned
	}
	
	public func dsaVerify(withSignature signature: Data, publicKey pubK: Data, privateKey privK: Data) -> Bool {
		let dsa = DSAAuth(publicKey: pubK, privateKey: privK)
		let verify = dsa.verify(signature: signature, digest: self)
		return verify
	}
}

extension String {
	public func hmacAuthCode(withKey key: Data, hashFunction: AuthHashFunction) -> Data? {
		if let data = self.data(using: .utf8) {
			return data.hmacAuthCode(withKey: key, hashFunction: hashFunction)
		}
		return nil
	}
	
	public func dsaSign(publicKey pubK: Data, privateKey privK: Data) -> Data? {
		if let data = self.data(using: .utf8) {
			return data.dsaSign(publicKey: pubK, privateKey: privK)
		}
		return nil
	}
	
	public func dsaVerify(withSignature signature: Data, publicKey pubK: Data, privateKey privK: Data) -> Bool {
		if let data = self.data(using: .utf8) {
			return data.dsaVerify(withSignature: signature, publicKey: pubK, privateKey: privK)
		}
		return false
	}
}
