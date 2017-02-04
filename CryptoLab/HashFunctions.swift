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
