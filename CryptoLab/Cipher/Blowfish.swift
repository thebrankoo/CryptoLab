//
//  Blowfish.swift
//  CryptoLab
//
//  Created by Branko Popovic on 2/14/17.
//  Copyright © 2017 Branko Popovic. All rights reserved.
//

import Foundation
import OpenSSL

/**
Blowfish specific encryption mode
*/
public enum BlowfishEncryptMode {
	/**
	Encrypts or decrypts the first 64 bits of data. If larger, everything after the first 64 bits is ignored.
	*/
	case ecb
	
	/**
	Encrypts or decrypts the 64 bits chunks. Initialization vector must be 8 byte long.
	*/
	case cbc
	
	/**
	Mode for Blowfish with 64 bit feedback. It uses the same parameters as  CFB64.
	*/
	case ofb64
	
	/**
	Mode for Blowfish with 64 bit feedback. Initialization vector must be 8 byte long.
	*/
	case cfb64
}

/**
Blowfish encryption/decryption class
*/
public class BlowfishCipher: NSObject, Cryptor {
	fileprivate let coreCipher: BlowfishCoreCipher
	
	/**
	Encryption key
	*/
	public let key: Data
	
	/**
	Creates new BlowfishCipher object with key, initialization vector and enceyption mode
	
	- parameters key: Encryption/decryption key
	- parameters iv: Initialization vector
	- parameters encryptionMode: Blowfish cipher mode
	*/
	public init(key: Data, iv: Data?, encryptionMode: BlowfishEncryptMode) {
		coreCipher = BlowfishCoreCipher(key: key, iv: iv, encryptionMode: encryptionMode)
		self.key = key
		super.init()
	}
	
	//MARK: Cryptor protocol
	
	public func encrypt(data dataToEncrypt: Data) throws -> Data {
		if let encrypted = coreCipher.encrypt(data: dataToEncrypt) {
			return encrypted
		}
		throw CipherError.cipherProcessFail(reason: CipherErrorReason.cipherEncryption)
	}
	
	public func decrypt(data dataToDecrypt: Data) throws -> Data {
		if let decrypted = coreCipher.decrypt(data: dataToDecrypt) {
			return decrypted
		}
		throw CipherError.cipherProcessFail(reason: CipherErrorReason.cipherDecryption)
	}
}

class BlowfishCoreCipher: NSObject {
	private let blowfishKey: UnsafeMutablePointer<BF_KEY>
	fileprivate let key: Data
	
	fileprivate let originalIV: Data?
	fileprivate var iv: Data?
	
	fileprivate let mode: BlowfishEncryptMode
	
	fileprivate init(key: Data, iv: Data?, encryptionMode: BlowfishEncryptMode) {
		self.key = key
		self.blowfishKey = UnsafeMutablePointer<BF_KEY>.allocate(capacity: MemoryLayout<BF_KEY>.size)
		self.originalIV = iv
		self.mode = encryptionMode
		
		BF_set_key(blowfishKey, Int32(key.count), key.makeUInt8DataPointer())
		super.init()
	}
	
	fileprivate func encrypt(data toEncrypt: Data) -> Data? {
		resetIV()
		
		switch mode {
		case .ecb:
			return ecbEncrypt(data: toEncrypt)
		case .cbc:
			if let iv = iv {
				return cbcEncrypt(data: toEncrypt, withIV: iv)
			}
			return nil
			
		case .ofb64:
			if let iv = iv {
				return ofb64Encrypt(data: toEncrypt, withIV: iv)
			}
			return nil
		case .cfb64:
			if let iv = iv {
				return cfb64Encrypt(data: toEncrypt, withIV: iv)
			}
			return nil
		}
	}
	
	fileprivate func decrypt(data toDecrypt: Data) -> Data? {
		resetIV()
		
		switch mode {
		case .ecb:
			return ecbDecrypt(data: toDecrypt)
		case .cbc:
			if let iv = iv {
				return cbcDecrypt(data: toDecrypt, withIV: iv)
			}
			return nil
			
		case .ofb64:
			if let iv = iv {
				return ofb64Decrypt(data: toDecrypt, withIV: iv)
			}
			return nil
		case .cfb64:
			if let iv = iv {
				return cfb64Decrypt(data: toDecrypt, withIV: iv)
			}
			return nil
		}

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
		
		BF_cbc_encrypt(inArray, &outArray, toEncrypt.count, blowfishKey, iv, BF_ENCRYPT)
		
		return Data(outArray)
	}
	
	fileprivate func cbcDecrypt(data toDecrypt: Data, withIV initv: Data) -> Data {
		var outArray = Data.makeUInt8EmptyArray(ofSize: toDecrypt.count)
		let inArray = toDecrypt.makeUInt8DataPointer()
		let iv = initv.makeUInt8DataPointer()
	
		BF_cbc_encrypt(inArray, &outArray, toDecrypt.count, blowfishKey, iv, BF_DECRYPT)
		
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
		
		BF_cfb64_encrypt(inArray, &outArray, toEncrypt.count, blowfishKey, iv, &num, BF_ENCRYPT)
		
		return Data(outArray)
	}
	
	fileprivate func cfb64Decrypt(data toDecrypt: Data, withIV initv: Data) -> Data {
		var outArray = Data.makeUInt8EmptyArray(ofSize: toDecrypt.count)
		let inArray = toDecrypt.makeUInt8DataPointer()
		let iv = initv.makeUInt8DataPointer()
		var num: Int32 = 0
		
		BF_cfb64_encrypt(inArray, &outArray, toDecrypt.count, blowfishKey, iv, &num, BF_DECRYPT)
		
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

		let data = cfb64Decrypt(data: toDecrypt, withIV: initv)
		
		return data
	}
	
	fileprivate func resetIV() {
		self.iv = self.originalIV
	}
}
