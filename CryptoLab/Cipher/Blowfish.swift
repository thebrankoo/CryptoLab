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
	
	public func cbcEncrypt(data toEncrypt: Data, withIV initv: Data) -> Data {
		var outArray = Data.makeUInt8EmptyArray(ofSize: 118)
		let inArray = toEncrypt.makeUInt8DataPointer()
		let iv = initv.makeUInt8DataPointer()
		
		BF_cbc_encrypt(inArray, &outArray, initv.count, blowfishKey, iv, BF_ENCRYPT)
		
		return Data(outArray)
	}
	
	public func cbcDecrypt(data toEncrypt: Data, withIV initv: Data) -> Data {
		var outArray = Data.makeUInt8EmptyArray(ofSize: 118)
		let inArray = toEncrypt.makeUInt8DataPointer()
		let iv = initv.makeUInt8DataPointer()
		
		BF_cbc_encrypt(inArray, &outArray, initv.count, blowfishKey, iv, BF_DECRYPT)
		
		return Data(outArray)
	}
	
	public func cfb64Encrypt(data toEncrypt: Data, withIV initv: Data) -> Data {
		var outArray = Data.makeUInt8EmptyArray(ofSize: 118)
		let inArray = toEncrypt.makeUInt8DataPointer()
		let iv = initv.makeUInt8DataPointer()
		var num: Int32 = 0
		
		BF_cfb64_encrypt(inArray, &outArray, initv.count, blowfishKey, iv, &num, BF_ENCRYPT)
		
		return Data(outArray)
	}
	
	public func cfb64Decrypt(data toEncrypt: Data, withIV initv: Data) -> Data {
		var outArray = Data.makeUInt8EmptyArray(ofSize: 118)
		let inArray = toEncrypt.makeUInt8DataPointer()
		let iv = initv.makeUInt8DataPointer()
		var num: Int32 = 0
		
		BF_cfb64_encrypt(inArray, &outArray, initv.count, blowfishKey, iv, &num, BF_DECRYPT)
		
		return Data(outArray)
	}
	
	public func ofb64Encrypt(data toEncrypt: Data, withIV initv: Data) -> Data {
		var outArray = Data.makeUInt8EmptyArray(ofSize: 118)
		let inArray = toEncrypt.makeUInt8DataPointer()
		let iv = initv.makeUInt8DataPointer()
		var num: Int32 = 0
		
		BF_ofb64_encrypt(inArray, &outArray, initv.count, blowfishKey, iv, &num)
		
		return Data(outArray)
	}
}
