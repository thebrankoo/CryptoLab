/**
- Author: Branko Popovic
*/


//
//  HMAC.swift
//  CryptoLab
//
//  Created by Branko Popovic on 3/1/17.
//  Copyright © 2017 Branko Popovic. All rights reserved.
//

import Foundation
import OpenSSL

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

class HMACCoreAuth: NSObject {
	fileprivate let key: Data
	fileprivate let hashFunction: AuthHashFunction
	fileprivate var context: UnsafeMutablePointer<HMAC_CTX>?
	
	init(key: Data, hashFunction: AuthHashFunction) {
		self.key = key
		self.hashFunction = hashFunction
		super.init()
	}
	
	//MARK: Auth Code
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

class HMACSignVerifyUnit: NSObject {
	var context: UnsafeMutablePointer<EVP_MD_CTX>
	let hashFunction: AuthHashFunction
	let key: Data
	
	init(key: Data, hashFunction: AuthHashFunction) {
		context = EVP_MD_CTX_create()
		self.hashFunction = hashFunction
		self.key = key
		
		super.init()
	}
	
	func initSignUnit(){
		let digestInitError = EVP_DigestInit_ex(context, hashFunction.value(), nil)
		if digestInitError != 1 {
			//init error
		}
		if let pkey = generateEVPPkey(fromData: key) {
			let digestSignInitError = EVP_DigestSignInit(context, nil, hashFunction.value(), nil, pkey)
			if digestSignInitError != 1 {
				//init error
			}
		}
		else {
			//init error
		}
	}
	
	func updateSignUnit(withData data: Data) {
		//let updateError = EVP_Update  // EVP_DigestSignUpdate(context, data.makeUInt8DataPointer(), data.count)
		
//		if updateError != 1 {
//			//update error
//		}
	}
	
	func finalSignUnit() -> UnsafeMutablePointer<UInt8> {
		let result = UnsafeMutablePointer<UInt8>.allocate(capacity: MemoryLayout<UInt8.Stride>.size)
		let resultSize = UnsafeMutablePointer<Int>.allocate(capacity: MemoryLayout<Int.Stride>.size)
		let finalError = EVP_DigestSignFinal(context, result, resultSize)
		
		if finalError != 1 {
			//final error
		}
		
		return result
	}
	
	func initVerifyUnit() {
		context = EVP_MD_CTX_create()
		let digestInitError = EVP_DigestInit_ex(context, hashFunction.value(), nil)
		if digestInitError != 1 {
			//init error
		}
		if let pkey = generateEVPPkey(fromData: key) {
			let digestSignInitError = EVP_DigestSignInit(context, nil, hashFunction.value(), nil, pkey)
			if digestSignInitError != 1 {
				//init error
			}
		}
		else {
			//init error
		}
	}
	
	func generateEVPPkey(fromData data: Data) -> UnsafeMutablePointer<EVP_PKEY>? {
		let bioStruct : UnsafeMutablePointer<BIO> = BIO_new(BIO_s_mem())
		BIO_write(bioStruct, ((data as NSData?)?.bytes)!, Int32(data.count))
		
		let pkey = PEM_read_bio_PUBKEY(bioStruct, nil, nil, nil)
		
		return pkey
	}
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
}
