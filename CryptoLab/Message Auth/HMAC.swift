//
//  HMAC.swift
//  CryptoLab
//
//  Created by Branko Popovic on 3/1/17.
//  Copyright © 2017 Branko Popovic. All rights reserved.
//

import Foundation
import OpenSSL

/*
OPENSSL_EXPORT const EVP_MD *EVP_md4(void);
OPENSSL_EXPORT const EVP_MD *EVP_md5(void);
OPENSSL_EXPORT const EVP_MD *EVP_sha1(void);
OPENSSL_EXPORT const EVP_MD *EVP_sha224(void);
OPENSSL_EXPORT const EVP_MD *EVP_sha256(void);
OPENSSL_EXPORT const EVP_MD *EVP_sha384(void);
OPENSSL_EXPORT const EVP_MD *EVP_sha512(void);
/* EVP_md5_sha1 is a TLS-specific |EVP_MD| which computes the concatenation of
* MD5 and SHA-1, as used in TLS 1.1 and below. */
OPENSSL_EXPORT const EVP_MD *EVP_md5_sha1(void);
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

public class HMACAuth: NSObject {
	fileprivate let coreHMAC: HMACCoreAuth
	
	public init(key: Data, hashFunction: AuthHashFunction) {
		coreHMAC = HMACCoreAuth(key: key, hashFunction: hashFunction)
		super.init()
	}
	
	public func authenticationCode(forData data: Data) -> Data? {
		let result = coreHMAC.authenticationCode(forData: data)
		if let rawData = result.result {
			return Data(bytes: rawData, count: Int(result.resultSize.pointee))
		}
		return nil
	}
	
	public func update(withData data: Data) {
		if !isUpdateInProcess() {
			coreHMAC.authCodeInit()
		}
		coreHMAC.authCodeUpdate(withData: data)
	}
	
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

class HMACCoreAuth: NSObject {
	fileprivate let key: Data
	fileprivate let hashFunction: AuthHashFunction
	fileprivate var context: UnsafeMutablePointer<HMAC_CTX>?
	
	init(key: Data, hashFunction: AuthHashFunction) {
		self.key = key
		self.hashFunction = hashFunction
		super.init()
	}
	
	fileprivate func authenticationCode(forData data: Data) -> (result: UnsafeMutablePointer<UInt8>?, resultSize: UnsafeMutablePointer<UInt32>) {
		let dataPointer = data.makeUInt8DataPointer()
		let dataLen = Int(data.count)
		let keyPointer = key.makeUInt8DataPointer()
		let keyLen = Int32(key.count)
		let resultSize = UnsafeMutablePointer<UInt32>.allocate(capacity: MemoryLayout<UInt32.Stride>.size)
		
		let result = HMAC(hashFunction.value(), keyPointer, keyLen, dataPointer, dataLen, nil, resultSize)
		return (result, resultSize)
	}
	
	fileprivate func authCodeInit() {
		self.context = UnsafeMutablePointer<HMAC_CTX>.allocate(capacity: MemoryLayout<HMAC_CTX>.size)
		HMAC_CTX_init(self.context)
		
		let keyPointer = key.makeUInt8DataPointer()
		let keyLen = Int32(key.count)
		HMAC_Init(self.context, keyPointer, keyLen, hashFunction.value())
	}
	
	fileprivate func authCodeUpdate(withData data: Data) {
		let dataPointer = data.makeUInt8DataPointer()
		let dataLen = Int(data.count)
		HMAC_Update(self.context, dataPointer, dataLen)
	}
	
	fileprivate func authCodeFinish() -> (result: Array<UInt8>?, resultSize: UnsafeMutablePointer<UInt32>) {
		var resultData = Data.makeUInt8EmptyArray(ofSize: Int(hashFunction.digestLength()))
		let resultSize = UnsafeMutablePointer<UInt32>.allocate(capacity: MemoryLayout<UInt32.Stride>.size)
		HMAC_Final(self.context, &resultData, resultSize)
		HMAC_CTX_cleanup(self.context)
		self.context?.deallocate(capacity: MemoryLayout<HMAC_CTX>.size)
		self.context = nil
		return (resultData, resultSize)
	}
}
