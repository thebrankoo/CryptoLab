//
//  CoreHMAC.swift
//  CryptoLab
//
//  Created by Branko Popovic on 4/26/17.
//  Copyright © 2017 Branko Popovic. All rights reserved.
//

import Foundation
import OpenSSL

class HMACCoreAuth: NSObject {
	let key: Data
	let hashFunction: AuthHashFunction
	var context: UnsafeMutablePointer<HMAC_CTX>?
	
	init(key: Data, hashFunction: AuthHashFunction) {
		self.key = key
		self.hashFunction = hashFunction
		super.init()
	}
	
	//MARK: Auth Code
	func authenticationCode(forData data: Data) -> (result: UnsafeMutablePointer<UInt8>?, resultSize: UnsafeMutablePointer<UInt32>) {
		let dataPointer = data.makeUInt8DataPointer()
		let dataLen = Int(data.count)
		let keyPointer = key.makeUInt8DataPointer()
		let keyLen = Int32(key.count)
		let resultSize = UnsafeMutablePointer<UInt32>.allocate(capacity: MemoryLayout<UInt32.Stride>.size)
		
		let result = HMAC(hashFunction.value(), keyPointer, keyLen, dataPointer, dataLen, nil, resultSize)
		return (result, resultSize)
	}
	
	func authCodeInit() {
		self.context = UnsafeMutablePointer<HMAC_CTX>.allocate(capacity: MemoryLayout<HMAC_CTX>.size)
		HMAC_CTX_init(self.context)
		
		let keyPointer = key.makeUInt8DataPointer()
		let keyLen = Int32(key.count)
		HMAC_Init(self.context, keyPointer, keyLen, hashFunction.value())
	}
	
	func authCodeUpdate(withData data: Data) {
		let dataPointer = data.makeUInt8DataPointer()
		let dataLen = Int(data.count)
		HMAC_Update(self.context, dataPointer, dataLen)
	}
	
	func authCodeFinish() -> (result: Array<UInt8>?, resultSize: UnsafeMutablePointer<UInt32>) {
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
