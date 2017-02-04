//
//  HashFunction.swift
//  CryptoLab
//
//  Created by Branko Popovic on 1/30/17.
//  Copyright © 2017 Branko Popovic. All rights reserved.
//

import Foundation
import OpenSSL

protocol HashingFunction {
	func hash(data dataToHash: Data) -> Data
}

public class MD5Hash: NSObject, HashingFunction {
	
	/**
	MD5 hash function for provided data
	- parameter: Data to hash
	- returns: MD5 hash
	*/
	public func hash(data dataToHash: Data) -> Data {
		
		//prepare structures
		var md5Data = [UInt8](repeating: UInt8(), count: Int(MD5_DIGEST_LENGTH))
		var data = Data(dataToHash)
		let dataSize = data.count
		let dataPointer = UnsafeMutablePointer<UInt8>(mutating: (data as NSData).bytes.bindMemory(to: UInt8.self, capacity: data.count))
		
		//calculate md5
		MD5(dataPointer, dataSize, &md5Data)
		
		//destroy structures
//		dataPointer.deinitialize()
//		dataPointer.deallocate(capacity: dataSize)
		
		return Data(md5Data)
	}
}

public class SHA1Hash: NSObject, HashingFunction {
	
	/**
	SHA1 hash function for provided data
	- parameter: Data to hash
	- returns: SHA1 hash
	*/
	public func hash(data dataToHash: Data) -> Data {
		//prepare structures
		var sha1Data = [UInt8](repeating: UInt8(), count: Int(SHA_DIGEST_LENGTH))
		var data = Data(dataToHash)
		let dataSize = data.count
		let dataPointer = UnsafeMutablePointer<UInt8>(mutating: (data as NSData).bytes.bindMemory(to: UInt8.self, capacity: data.count))
		
		//calculate sha1
		SHA1(dataPointer, dataSize, &sha1Data)
		
		//destroy structures
//		dataPointer.deinitialize()
//		dataPointer.deallocate(capacity: dataSize)
		
		return Data(sha1Data)
	}
}

public class SHA224Hash: NSObject, HashingFunction {
	
	/**
	SHA224 hash function for provided data
	- parameter: Data to hash
	- returns: SHA224 hash
	*/
	public func hash(data dataToHash: Data) -> Data {
		//prepare structures
		var sha224Data = [UInt8](repeating: UInt8(), count: Int(SHA224_DIGEST_LENGTH))
		var data = Data(dataToHash)
		let dataSize = data.count
		let dataPointer = UnsafeMutablePointer<UInt8>(mutating: (data as NSData).bytes.bindMemory(to: UInt8.self, capacity: data.count))
		
		//calculate sha1
		SHA224(dataPointer, dataSize, &sha224Data)
		
		//destroy structures
		//		dataPointer.deinitialize()
		//		dataPointer.deallocate(capacity: dataSize)
		
		return Data(sha224Data)
	}
}

public class SHA256Hash: NSObject, HashingFunction {
	
	/**
	SHA256 hash function for provided data
	- parameter: Data to hash
	- returns: SHA256 hash
	*/
	public func hash(data dataToHash: Data) -> Data {
		//prepare structures
		var sha256Data = [UInt8](repeating: UInt8(), count: Int(SHA256_DIGEST_LENGTH))
		var data = Data(dataToHash)
		let dataSize = data.count
		let dataPointer = UnsafeMutablePointer<UInt8>(mutating: (data as NSData).bytes.bindMemory(to: UInt8.self, capacity: data.count))
		
		//calculate sha1
		SHA256(dataPointer, dataSize, &sha256Data)
		
		//destroy structures
		//		dataPointer.deinitialize()
		//		dataPointer.deallocate(capacity: dataSize)
		
		return Data(sha256Data)
	}
}

public class SHA384Hash: NSObject, HashingFunction {
	
	/**
	SHA384 hash function for provided data
	- parameter: Data to hash
	- returns: SHA384 hash
	*/
	public func hash(data dataToHash: Data) -> Data {
		//prepare structures
		var sha384Data = [UInt8](repeating: UInt8(), count: Int(SHA384_DIGEST_LENGTH))
		var data = Data(dataToHash)
		let dataSize = data.count
		let dataPointer = UnsafeMutablePointer<UInt8>(mutating: (data as NSData).bytes.bindMemory(to: UInt8.self, capacity: data.count))
		
		//calculate sha1
		SHA384(dataPointer, dataSize, &sha384Data)
		
		//destroy structures
		//		dataPointer.deinitialize()
		//		dataPointer.deallocate(capacity: dataSize)
		
		return Data(sha384Data)
	}
}

public class SHA512Hash: NSObject, HashingFunction {
	
	/**
	SHA512 hash function for provided data
	- parameter: Data to hash
	- returns: SHA512 hash
	*/
	public func hash(data dataToHash: Data) -> Data {
		//prepare structures
		var sha512Data = [UInt8](repeating: UInt8(), count: Int(SHA512_DIGEST_LENGTH))
		var data = Data(dataToHash)
		let dataSize = data.count
		let dataPointer = UnsafeMutablePointer<UInt8>(mutating: (data as NSData).bytes.bindMemory(to: UInt8.self, capacity: data.count))
		
		//calculate sha1
		SHA512(dataPointer, dataSize, &sha512Data)
		
		//destroy structures
		//		dataPointer.deinitialize()
		//		dataPointer.deallocate(capacity: dataSize)
		
		return Data(sha512Data)
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
