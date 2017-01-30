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
	
	public func hash(data dataToHash: Data) -> Data {
		var md5Data = [UInt8](repeating: UInt8(), count: Int(MD5_DIGEST_LENGTH))
		var data = Data(dataToHash)
		var md5Context = MD5_CTX()
		
		let initResult = MD5_Init(&md5Context)
		let updateResult = MD5_Update(&md5Context, &data, data.count)
		let finalResult = MD5_Final(&md5Data, &md5Context)
		
		print("Init result \(initResult)")
		print("Update result \(updateResult)")
		print("Final result \(finalResult)")
		print("Hash data \(md5Data)")
		
		return Data(md5Data)
	}
}
