//
//  OldFuncitonKeeper.swift
//  CryptoLab
//
//  Created by Branko Popovic on 2/4/17.
//  Copyright © 2017 Branko Popovic. All rights reserved.
//

import Foundation
/**
MD5 hash function for provided data
- parameter: Data to hash
- returns: MD5 hash
*/
//	public func hash(data dataToHash: Data) -> Data {
//
//
//		var md5Data = [UInt8](repeating: UInt8(), count: Int(MD5_DIGEST_LENGTH))
//		var data = Data(dataToHash)
//		let dataSize = data.count
//		let dataPointer = UnsafeMutablePointer<UInt8>(mutating: (data as NSData).bytes.bindMemory(to: UInt8.self, capacity: data.count))
//
//		MD5(dataPointer, dataSize, &md5Data)
//
//		return Data(md5Data)
//	}

//	public func hash(data dataToHash: Data) -> Data {
//		update(withData: dataToHash)
//		let finalData = finishBlock()
//		return finalData
//	}
