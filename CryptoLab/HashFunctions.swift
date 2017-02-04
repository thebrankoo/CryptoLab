//
//  HashFunction.swift
//  CryptoLab
//
//  Created by Branko Popovic on 1/30/17.
//  Copyright © 2017 Branko Popovic. All rights reserved.
//

import Foundation
import OpenSSL


public protocol HashingFunction {
	//func update(withData data: Data)
	func finishBlock() -> Data
}

extension HashingFunction {
	public func hash(data dataToHash: Data) -> Data {
		update(withData: dataToHash)
		let finalData = finishBlock()
		return finalData
	}
	
	public func update(withData data: Data) {
		let dataSize = data.count
		let dataPointer = UnsafeMutablePointer<UInt8>(mutating: (data as NSData).bytes.bindMemory(to: UInt8.self, capacity: dataSize))
		
		if let hashFunc = self as? MD5Hash {
			MD5_Update(&hashFunc.context, dataPointer, dataSize)
		}
		else if let hashFunc = self as? SHA1Hash {
			SHA1_Update(&hashFunc.context, dataPointer, dataSize)
		}
		else if let hashFunc = self as? SHA224Hash {
			SHA224_Update(&hashFunc.context, dataPointer, dataSize)
		}
		else if let hashFunc = self as? SHA256Hash {
			SHA256_Update(&hashFunc.context, dataPointer, dataSize)
		}
		else if let hashFunc = self as? SHA384Hash {
			SHA384_Update(&hashFunc.context, dataPointer, dataSize)
		}
		else if let hashFunc = self as? SHA512Hash {
			SHA512_Update(&hashFunc.context, dataPointer, dataSize)
		}
	}
}

public class MD5Hash: NSObject, HashingFunction {
	
	fileprivate var context: MD5_CTX
	
	override public init() {
		context = MD5_CTX()
		MD5_Init(&context)
		super.init()
	}
	
	public func finishBlock() -> Data {
		var finalData = [UInt8](repeating: UInt8(), count: Int(MD5_DIGEST_LENGTH))
		MD5_Final(&finalData, &context)
		
		return Data(finalData)
	}
}

public class SHA1Hash: NSObject, HashingFunction {
	fileprivate var context: SHA_CTX
	
	override public init() {
		context = SHA_CTX()
		SHA1_Init(&context)
		super.init()
	}
	
	public func finishBlock() -> Data {
		var finalData = [UInt8](repeating: UInt8(), count: Int(SHA_DIGEST_LENGTH))
		SHA1_Final(&finalData, &context)
		
		return Data(finalData)
	}
	
}

public class SHA224Hash: NSObject, HashingFunction {
	
	fileprivate var context: SHA256_CTX
	
	override public init() {
		context = SHA256_CTX()
		SHA224_Init(&context)
		super.init()
	}
	
	public func finishBlock() -> Data {
		var finalData = [UInt8](repeating: UInt8(), count: Int(SHA224_DIGEST_LENGTH))
		SHA224_Final(&finalData, &context)
		
		return Data(finalData)
	}
}

public class SHA256Hash: NSObject, HashingFunction {
	
	fileprivate var context: SHA256_CTX
	
	override public init() {
		context = SHA256_CTX()
		SHA256_Init(&context)
		super.init()
	}
	
	public func finishBlock() -> Data {
		var finalData = [UInt8](repeating: UInt8(), count: Int(SHA256_DIGEST_LENGTH))
		SHA256_Final(&finalData, &context)
		
		return Data(finalData)
	}
}

public class SHA384Hash: NSObject, HashingFunction {
	
	fileprivate var context: SHA512_CTX
	
	override public init() {
		context = SHA512_CTX()
		SHA384_Init(&context)
		super.init()
	}
	
	public func finishBlock() -> Data {
		var finalData = [UInt8](repeating: UInt8(), count: Int(SHA384_DIGEST_LENGTH))
		SHA384_Final(&finalData, &context)
		
		return Data(finalData)
	}
}

public class SHA512Hash: NSObject, HashingFunction {
	
	fileprivate var context: SHA512_CTX
	
	override public init() {
		context = SHA512_CTX()
		SHA512_Init(&context)
		super.init()
	}
	
	public func finishBlock() -> Data {
		var finalData = [UInt8](repeating: UInt8(), count: Int(SHA512_DIGEST_LENGTH))
		SHA512_Final(&finalData, &context)
		
		return Data(finalData)
	}
}

public extension Data {
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

public extension String {
	
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
