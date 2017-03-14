//
//  HashFunction.swift
//  CryptoLab
//
//  Created by Branko Popovic on 1/30/17.
//  Copyright © 2017 Branko Popovic. All rights reserved.
//

import Foundation
import OpenSSL


protocol CoreHashingFunction {
	func update(pointerData dataPointer: UnsafeMutablePointer<UInt8>, size dataSize: Int)
	func finishBlock() -> Data
}

extension CoreHashingFunction {
	func hash(data dataToHash: Data) -> Data {
		update(withData: dataToHash)
		let finalData = finishBlock()
		return finalData
	}
	
	func update(withData data: Data) {
		let dataSize = data.count
		let dataPointer = UnsafeMutablePointer<UInt8>(mutating: (data as NSData).bytes.bindMemory(to: UInt8.self, capacity: dataSize))
		update(pointerData: dataPointer, size: dataSize)
	}
}

 class MD5CoreHash: NSObject, CoreHashingFunction {
	
	fileprivate var context: MD5_CTX
	
	override  init() {
		context = MD5_CTX()
		MD5_Init(&context)
		super.init()
	}
	
	 func update(pointerData dataPointer: UnsafeMutablePointer<UInt8>, size dataSize: Int) {
		MD5_Update(&context, dataPointer, dataSize)
	}
	
	 func finishBlock() -> Data {
		var finalData = [UInt8](repeating: UInt8(), count: Int(MD5_DIGEST_LENGTH))
		MD5_Final(&finalData, &context)
		
		return Data(finalData)
	}
}

 class SHA1CoreHash: NSObject, CoreHashingFunction {
	fileprivate var context: SHA_CTX
	
	override  init() {
		context = SHA_CTX()
		SHA1_Init(&context)
		super.init()
	}
	
	 func update(pointerData dataPointer: UnsafeMutablePointer<UInt8>, size dataSize: Int) {
		SHA1_Update(&context, dataPointer, dataSize)
	}
	
	 func finishBlock() -> Data {
		var finalData = [UInt8](repeating: UInt8(), count: Int(SHA_DIGEST_LENGTH))
		SHA1_Final(&finalData, &context)
		
		return Data(finalData)
	}
	
}

 class SHA224CoreHash: NSObject, CoreHashingFunction {
	
	fileprivate var context: SHA256_CTX
	
	override  init() {
		context = SHA256_CTX()
		SHA224_Init(&context)
		super.init()
	}
	
	 func update(pointerData dataPointer: UnsafeMutablePointer<UInt8>, size dataSize: Int) {
		SHA224_Update(&context, dataPointer, dataSize)
	}
	
	 func finishBlock() -> Data {
		var finalData = [UInt8](repeating: UInt8(), count: Int(SHA224_DIGEST_LENGTH))
		SHA224_Final(&finalData, &context)
		
		return Data(finalData)
	}
}

 class SHA256CoreHash: NSObject, CoreHashingFunction {
	
	fileprivate var context: SHA256_CTX
	
	override  init() {
		context = SHA256_CTX()
		SHA256_Init(&context)
		super.init()
	}
	
	 func update(pointerData dataPointer: UnsafeMutablePointer<UInt8>, size dataSize: Int) {
		SHA256_Update(&context, dataPointer, dataSize)
	}
	
	 func finishBlock() -> Data {
		var finalData = [UInt8](repeating: UInt8(), count: Int(SHA256_DIGEST_LENGTH))
		SHA256_Final(&finalData, &context)
		
		return Data(finalData)
	}
}

 class SHA384CoreHash: NSObject, CoreHashingFunction {
	
	fileprivate var context: SHA512_CTX
	
	override  init() {
		context = SHA512_CTX()
		SHA384_Init(&context)
		super.init()
	}
	
	 func update(pointerData dataPointer: UnsafeMutablePointer<UInt8>, size dataSize: Int) {
		SHA384_Update(&context, dataPointer, dataSize)
	}
	
	 func finishBlock() -> Data {
		var finalData = [UInt8](repeating: UInt8(), count: Int(SHA384_DIGEST_LENGTH))
		SHA384_Final(&finalData, &context)
		
		return Data(finalData)
	}
}

 class SHA512CoreHash: NSObject, CoreHashingFunction {
	
	fileprivate var context: SHA512_CTX
	
	override  init() {
		context = SHA512_CTX()
		SHA512_Init(&context)
		super.init()
	}
	
	 func update(pointerData dataPointer: UnsafeMutablePointer<UInt8>, size dataSize: Int) {
		SHA512_Update(&context, dataPointer, dataSize)
	}
	
	 func finishBlock() -> Data {
		var finalData = [UInt8](repeating: UInt8(), count: Int(SHA512_DIGEST_LENGTH))
		SHA512_Final(&finalData, &context)
		
		return Data(finalData)
	}
}
