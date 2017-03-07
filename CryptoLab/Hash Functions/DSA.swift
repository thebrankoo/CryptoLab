//
//  DSA.swift
//  CryptoLab
//
//  Created by Branko Popovic on 3/7/17.
//  Copyright © 2017 Branko Popovic. All rights reserved.
//

import Foundation
import OpenSSL

public class DSACore: NSObject {
	
	let key: Data?
	public static var dsaKey: UnsafeMutablePointer<DSA>?
	
	init(key: Data?) {
		self.key = key
		super.init()
	}
	
	public func generateDSA() {
		//dsaKey = generateDSAPrivPubKeys(key: generateDSAKeyWithParameters())
	}
	
	func generateDSAPrivPubKeys(key: UnsafeMutablePointer<DSA>?) -> UnsafeMutablePointer<DSA>? {
		
		let dsaError = DSA_generate_key(key)
		
		if dsaError != 1 {
			print("DSA key generate error")
		}
		
		return key
	}
	
	func generateDSAKeyWithParameters() -> UnsafeMutablePointer<DSA>? {
		let bits = 1024
		let des = DSA_generate_parameters(Int32(bits), nil, 0, nil, nil, nil, nil)
		return des

	}
	
	public class func sign(data: Data) {
		let dataPointer = data.makeUInt8DataPointer()
		let dataSize = data.count
		let size = UInt32(DSA_size(self.dsaKey!))
		let dsaSize = UnsafeMutablePointer<UInt32>.allocate(capacity: MemoryLayout<UInt32.Stride>.size)
		dsaSize.pointee = size
		
		var result = Data.makeUInt8EmptyArray(ofSize: Int(size))
		
		let error = DSA_sign(0, dataPointer, Int32(dataSize), &result, dsaSize, dsaKey!)
		
	}
	
}
