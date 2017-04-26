//
//  HMAC.swift
//  CryptoLab
//
//  Created by Branko Popovic on 3/1/17.
//  Copyright © 2017 Branko Popovic. All rights reserved.
//

import Foundation
import OpenSSL

/**
Hash function for DSA authentication code generation
*/
public enum AuthHashFunction {
	case md4
	case md5
	case sha1
	case sha224
	case sha256
	case sha384
	case sha512
	
	func value() -> UnsafePointer<EVP_MD> {
		switch self {
		case .md4:
			return EVP_md4()
		case .md5:
			return EVP_md5()
		case .sha1:
			return EVP_sha1()
		case .sha224:
			return EVP_sha224()
		case .sha256:
			return EVP_sha256()
		case .sha384:
			return EVP_sha384()
		case .sha512:
			return EVP_sha512()
		}
	}
	
	func digestLength() -> Int32 {
		switch self {
		case .md4:
			return MD5_DIGEST_LENGTH
		case .md5:
			return MD5_DIGEST_LENGTH
		case .sha1:
			return SHA_DIGEST_LENGTH
		case .sha224:
			return SHA224_DIGEST_LENGTH
		case .sha256:
			return SHA256_DIGEST_LENGTH
		case .sha384:
			return SHA384_DIGEST_LENGTH
		case .sha512:
			return SHA512_DIGEST_LENGTH
		}
	}
}

/**
HMAC auth code generation calss
*/
public class HMACAuth: NSObject {
	fileprivate let coreHMAC: HMACCoreAuth
	
	/**
	Creates new HMACAuth object with key and hash function.
	
	- parameter key: Key that will be used
	- parameter hashFunction: Hash function that will be used
	*/
	public init(key: Data, hashFunction: AuthHashFunction) {
		coreHMAC = HMACCoreAuth(key: key, hashFunction: hashFunction)
		super.init()
	}
	
	/**
	Computes authentication code of data using the hash function provided in init 
	
	- parameter data: Data authentication code is computed for
	
	- returns: Authentication code for provided data
	*/
	public func authenticationCode(forData data: Data) -> Data? {
		let result = coreHMAC.authenticationCode(forData: data)
		if let rawData = result.result {
			return Data(bytes: rawData, count: Int(result.resultSize.pointee))
		}
		return nil
	}
	
	/**
	Updates current data with new data chunk.
	
	- parameter data: Data chunk that is added to current data
	*/
	public func update(withData data: Data) {
		if !isUpdateInProcess() {
			coreHMAC.authCodeInit()
		}
		coreHMAC.authCodeUpdate(withData: data)
	}
	
	/**
	Finishes computing authentication code of data chunks provided in update function
	
	- returns: Authentication code for provided data chunks or nil if authentication code can't be computed
	*/
	public func finish() -> Data? {
		let result = coreHMAC.authCodeFinish()
		
		if let resultData = result.result {
			return Data(resultData)
		}
		
		return nil
	}
	
	fileprivate func isUpdateInProcess() -> Bool {
		if let _ = coreHMAC.context {
			return true
		}
		return false
	}
}
