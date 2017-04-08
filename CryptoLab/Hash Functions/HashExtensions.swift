//
//  HashExtensions.swift
//  CryptoLab
//
//  Created by Branko Popovic on 3/13/17.
//  Copyright © 2017 Branko Popovic. All rights reserved.
//

import Foundation

 extension Data {
	/**
	MD5 hash of data
	
	- returns: MD5 data
	*/
	public func md5() -> Data {
		return MD5Hash().hash(data: self)
	}

	/**
	SHA1 hash of data
	
	- returns: SHA1 data
	*/
	public func sha1() -> Data {
		return SHA1Hash().hash(data: self)
	}

	/**
	SHA224 hash of data
	
	- returns: SHA224 data
	*/
	public func sha224() -> Data {
		return SHA224Hash().hash(data: self)
	}

	/**
	SHA256 hash of data
	
	- returns: SHA256 data
	*/
	public func sha256() -> Data {
		return SHA256Hash().hash(data: self)
	}

	/**
	SHA384 hash of data
	
	- returns: SHA384 data
	*/
	public func sha384() -> Data {
		return SHA384Hash().hash(data: self)
	}

	/**
	SHA512 hash of data
	
	- returns: SHA512 data
	*/
	public func sha512() -> Data {
		return SHA512Hash().hash(data: self)
	}
}

 extension String {
	/**
	MD5 hash of string
	
	- returns: MD5 data
	*/
	public func md5() -> Data? {
		if let selfData = self.data(using: .utf8) {
			return MD5Hash().hash(data: selfData)
		}
		return nil
	}

	/**
	SHA1 hash of string
	
	- returns: SHA1 data
	*/
	public func sha1() -> Data? {
		if let selfData = self.data(using: .utf8) {
			return MD5Hash().hash(data: selfData)
		}
		return nil
	}

	/**
	SHA224 hash of string
	
	- returns: SHA224 data
	*/
	public func sha224() -> Data? {
		if let selfData = self.data(using: .utf8) {
			return SHA224Hash().hash(data: selfData)
		}
		return nil
	}

	/**
	SHA256 hash of string
	
	- returns: SHA256 data
	*/
	public func sha256() -> Data? {
		if let selfData = self.data(using: .utf8) {
			return SHA256Hash().hash(data: selfData)
		}
		return nil
	}

	/**
	SHA384 hash of string
	
	- returns: SHA384 data
	*/
	public func sha384() -> Data? {
		if let selfData = self.data(using: .utf8) {
			return SHA384Hash().hash(data: selfData)
		}
		return nil	}

	public func sha512() -> Data? {
		if let selfData = self.data(using: .utf8) {
			return SHA512Hash().hash(data: selfData)
		}
		return nil
	}
}
