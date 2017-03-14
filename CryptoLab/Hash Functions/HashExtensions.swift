//
//  HashExtensions.swift
//  CryptoLab
//
//  Created by Branko Popovic on 3/13/17.
//  Copyright © 2017 Branko Popovic. All rights reserved.
//

import Foundation

 extension Data {
	func md5() -> Data {
		return MD5Hash().hash(data: self)
	}

	func sha1() -> Data {
		return SHA1Hash().hash(data: self)
	}

	func sha224() -> Data {
		return SHA224Hash().hash(data: self)
	}

	func sha256() -> Data {
		return SHA256Hash().hash(data: self)
	}

	func sha384() -> Data {
		return SHA384Hash().hash(data: self)
	}

	func sha512() -> Data {
		return SHA512Hash().hash(data: self)
	}
}

 extension String {
	func md5() -> Data? {
		if let selfData = self.data(using: .utf8) {
			return MD5Hash().hash(data: selfData)
		}
		return nil
	}

	func sha1() -> Data? {
		if let selfData = self.data(using: .utf8) {
			return MD5Hash().hash(data: selfData)
		}
		return nil
	}

	func sha224() -> Data? {
		if let selfData = self.data(using: .utf8) {
			return SHA224Hash().hash(data: selfData)
		}
		return nil
	}

	func sha256() -> Data? {
		if let selfData = self.data(using: .utf8) {
			return SHA256Hash().hash(data: selfData)
		}
		return nil
	}

	func sha384() -> Data? {
		if let selfData = self.data(using: .utf8) {
			return SHA384Hash().hash(data: selfData)
		}
		return nil	}

	func sha512() -> Data? {
		if let selfData = self.data(using: .utf8) {
			return SHA512Hash().hash(data: selfData)
		}
		return nil
	}
}
