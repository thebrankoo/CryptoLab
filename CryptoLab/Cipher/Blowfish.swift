//
//  Blowfish.swift
//  CryptoLab
//
//  Created by Branko Popovic on 2/14/17.
//  Copyright © 2017 Branko Popovic. All rights reserved.
//

import Foundation
import OpenSSL

public class BlowfishCipher: NSObject {
	
}

public class BlowfishCoreCipher: NSObject {
	private let blowfishKey: UnsafeMutablePointer<BF_KEY>
	
	public init(key: Data) {
		self.blowfishKey = UnsafeMutablePointer<BF_KEY>.allocate(capacity: MemoryLayout<BF_KEY>.size)
		BF_set_key(blowfishKey, Int32(key.count), key.makeUInt8DataPointer())
		super.init()
	}
	
	public func ecbEncrypt(data toEncrypt: Data) -> Data {
		var outArray = Data.makeUInt8EmptyArray(ofSize: 118)
		let inArray = toEncrypt.makeUInt8DataPointer()
		
		BF_ecb_encrypt(inArray, &outArray, blowfishKey, BF_ENCRYPT)
		
		return Data(outArray)
	}
	
	public func ecbDecrypt(data toDecrypt: Data) -> Data {
		var outArray = Data.makeUInt8EmptyArray(ofSize: 118)
		let inArray = toDecrypt.makeUInt8DataPointer()
		
		BF_ecb_encrypt(inArray, &outArray, blowfishKey, BF_DECRYPT)
		
		return Data(outArray)
	}
}
