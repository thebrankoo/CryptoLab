//
//  Blowfish.swift
//  CryptoLab
//
//  Created by Branko Popovic on 2/14/17.
//  Copyright © 2017 Branko Popovic. All rights reserved.
//

import Foundation
import OpenSSL

public enum BlowfishEncryptMode {
	case ecb
	case cbc
	case ofb64
	case cfb64
}

public class BlowfishCipher: NSObject {
	fileprivate let coreCipher: BlowfishCoreCipher
	public let key: Data
	
	public init(key: Data) {
		coreCipher = BlowfishCoreCipher(key: key)
		self.key = key
		super.init()
	}
	
	public func encrypt(data toEncrypt: Data, withIV iv: Data?, mode: BlowfishEncryptMode) -> Data? {
		switch mode {
		case .ecb:
			return coreCipher.ecbEncrypt(data: toEncrypt)
		case .cbc:
			if let iv = iv {
				return coreCipher.cbcEncrypt(data: toEncrypt, withIV: iv)
			}
			return nil
			
		case .ofb64:
			if let iv = iv {
				return coreCipher.ofb64Encrypt(data: toEncrypt, withIV: iv)
			}
			return nil
		case .cfb64:
			if let iv = iv {
				return coreCipher.cfb64Encrypt(data: toEncrypt, withIV: iv)
			}
			return nil
		}
	}
	
	public func decrypt(data toEncrypt: Data, withIV iv: Data?, mode: BlowfishEncryptMode) -> Data? {
		switch mode {
		case .ecb:
			return coreCipher.ecbDecrypt(data: toEncrypt)
		case .cbc:
			if let iv = iv {
				return coreCipher.cbcDecrypt(data: toEncrypt, withIV: iv)
			}
			return nil
			
		case .ofb64:
			if let iv = iv {
				return coreCipher.ofb64Decrypt(data: toEncrypt, withIV: iv)
			}
			return nil
		case .cfb64:
			if let iv = iv {
				return coreCipher.cfb64Decrypt(data: toEncrypt, withIV: iv)
			}
			return nil
		}
	}
}

class BlowfishCoreCipher: NSObject {
	private let blowfishKey: UnsafeMutablePointer<BF_KEY>
	fileprivate let key: Data
	
	fileprivate init(key: Data) {
		self.key = key
		self.blowfishKey = UnsafeMutablePointer<BF_KEY>.allocate(capacity: MemoryLayout<BF_KEY>.size)
		
		BF_set_key(blowfishKey, Int32(key.count), key.makeUInt8DataPointer())
		super.init()
	}
	
	/**
	ecb data len to encrypt must be multiply of 8
	ivec must be 8 bytes
	*/
	
	fileprivate func ecbEncrypt(data toEncrypt: Data) -> Data {
		var outArray = Data.makeUInt8EmptyArray(ofSize: 8)
		let inArray = toEncrypt.makeUInt8DataPointer()
		
		BF_ecb_encrypt(inArray, &outArray, blowfishKey, BF_ENCRYPT)
		
		return Data(outArray)
	}
	
	fileprivate func ecbDecrypt(data toDecrypt: Data) -> Data {
		var outArray = Data.makeUInt8EmptyArray(ofSize: 8)
		let inArray = toDecrypt.makeUInt8DataPointer()
		
		BF_ecb_encrypt(inArray, &outArray, blowfishKey, BF_DECRYPT)
		
		return Data(outArray)
	}
	
	/**
	cbc data len to encrypt can be var
	ivec must be 8 bytes
	*/
	fileprivate func cbcEncrypt(data toEncrypt: Data, withIV initv: Data) -> Data {
		var outArray = Data.makeUInt8EmptyArray(ofSize: toEncrypt.count)
		let inArray = toEncrypt.makeUInt8DataPointer()
		let iv = initv.makeUInt8DataPointer()
		
		BF_cbc_encrypt(inArray, &outArray, initv.count, blowfishKey, iv, BF_ENCRYPT)
		
		return Data(outArray)
	}
	
	fileprivate func cbcDecrypt(data toDecrypt: Data, withIV initv: Data) -> Data {
		var outArray = Data.makeUInt8EmptyArray(ofSize: toDecrypt.count)
		let inArray = toDecrypt.makeUInt8DataPointer()
		let iv = initv.makeUInt8DataPointer()
		
		BF_cbc_encrypt(inArray, &outArray, initv.count, blowfishKey, iv, BF_DECRYPT)
		
		return Data(outArray)
	}
	
	/**
	cfb64 data len can be variable
	ivec must be 8 bytes
	*/
	fileprivate func cfb64Encrypt(data toEncrypt: Data, withIV initv: Data) -> Data {
		var outArray = Data.makeUInt8EmptyArray(ofSize: toEncrypt.count)
		let inArray = toEncrypt.makeUInt8DataPointer()
		let iv = initv.makeUInt8DataPointer()
		var num: Int32 = 0
		
		BF_cfb64_encrypt(inArray, &outArray, initv.count, blowfishKey, iv, &num, BF_ENCRYPT)
		
		return Data(outArray)
	}
	
	fileprivate func cfb64Decrypt(data toDecrypt: Data, withIV initv: Data) -> Data {
		var outArray = Data.makeUInt8EmptyArray(ofSize: toDecrypt.count)
		let inArray = toDecrypt.makeUInt8DataPointer()
		let iv = initv.makeUInt8DataPointer()
		var num: Int32 = 0
		
		BF_cfb64_encrypt(inArray, &outArray, initv.count, blowfishKey, iv, &num, BF_DECRYPT)
		
		return Data(outArray)
	}
	
	/**
	ofb64 data len can be variable
	ivec must be 8 bytes
	*/
	fileprivate func ofb64Encrypt(data toEncrypt: Data, withIV initv: Data) -> Data {
		var outArray = Data.makeUInt8EmptyArray(ofSize: toEncrypt.count)
		let inArray = toEncrypt.makeUInt8DataPointer()
		let iv = initv.makeUInt8DataPointer()
		var num: Int32 = 0
		
		BF_ofb64_encrypt(inArray, &outArray, initv.count, blowfishKey, iv, &num)
		
		return Data(outArray)
	}
	
	fileprivate func ofb64Decrypt(data toDecrypt: Data, withIV initv: Data) -> Data {
//		var outArray = Data.makeUInt8EmptyArray(ofSize: toDecrypt.count)
//		let inArray = toDecrypt.makeUInt8DataPointer()
//		let iv = initv.makeUInt8DataPointer()
//		var num: Int32 = 0
//		
//		BF_ofb64_encrypt(inArray, &outArray, initv.count, blowfishKey, iv, &num)

		let data = ofb64Decrypt(data: toDecrypt, withIV: initv)
		
		return data
	}
}
