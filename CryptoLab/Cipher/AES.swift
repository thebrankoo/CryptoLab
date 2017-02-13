//
//  Ciphers.swift
//  CryptoLab
//
//  Created by Branko Popovic on 2/9/17.
//  Copyright © 2017 Branko Popovic. All rights reserved.
//

import Foundation
import OpenSSL

enum AESKeySize: Int {
	case aes128 = 16
	case aes256 = 32
	case aes192 = 24
	
	public static func isAES128(keySize key: Int) -> Bool {
		return AESKeySize(rawValue: key) == AESKeySize.aes128
	}
	
	public static func isAES256(keySize key: Int) -> Bool {
		return AESKeySize(rawValue: key) == AESKeySize.aes256
	}
	
	public static func isAES192(keySize key: Int) -> Bool {
		return AESKeySize(rawValue: key) == AESKeySize.aes192
	}
}

public enum BlockCipherMode {
	case cbc
	case ecb
	case cfb
	case ofb //dont reuse iv
	case ctr //dont reuse iv
	
	public static func isBlockModeCBC(blockMode: BlockCipherMode) -> Bool {
		return .cbc == blockMode
	}
	public static func isBlockModeECB(blockMode: BlockCipherMode) -> Bool {
		return .ecb == blockMode
	}
	public static func isBlockModeCFB(blockMode: BlockCipherMode) -> Bool {
		return .cfb == blockMode
	}
	public static func isBlockModeOFB(blockMode: BlockCipherMode) -> Bool {
		return .ofb == blockMode
	}
	public static func isBlockModeCTR(blockMode: BlockCipherMode) -> Bool {
		return .ctr == blockMode
	}
}

enum AESError: Error {
	case noInitParameters(reason: String)
}

enum CipherGeneralError: Error {
	case cipherProcessFail(reason: String)
	case invalidKey(reason: String)
}

public class AESCipher: NSObject {
	static let ivSize = 16
	let key: Data?
	let iv: Data?
	let blockMode: BlockCipherMode?
	
	fileprivate var aesCipher: UnsafePointer<EVP_CIPHER>?
	
	public init(key: Data, iv: Data, blockMode: BlockCipherMode) throws {
		self.key = key
		self.iv = iv
		self.blockMode = blockMode
		super.init()
		
		if isValid(cipherKey: key) == false { throw CipherGeneralError.invalidKey(reason: "AES Key must be of size: 16, 24 or 32 bytes") }
		decideAESCipher()
	}
	
	public func encrypt(data: Data) throws -> Data {
		
		let dataPointer = UnsafeMutablePointer<UInt8>(mutating: (data as NSData).bytes.bindMemory(to: UInt8.self, capacity: data.count))
		
		let ctx = EVP_CIPHER_CTX_new()
		
		if let key = self.key, let iv = self.iv {
			
			let keyPointer = UnsafeMutablePointer<UInt8>(mutating: (key as NSData).bytes.bindMemory(to: UInt8.self, capacity: key.count))
			let ivPointer = UnsafeMutablePointer<UInt8>(mutating: (iv as NSData).bytes.bindMemory(to: UInt8.self, capacity: iv.count))
			
			var resultData = [UInt8](repeating: UInt8(), count: key.count)
			let resultSize = UnsafeMutablePointer<Int32>.allocate(capacity: MemoryLayout<Int32.Stride>.size)
			
			let initCheck = EVP_EncryptInit(ctx, self.aesCipher, keyPointer, ivPointer)
			if initCheck == 0 {
				throw CipherGeneralError.cipherProcessFail(reason: "Encryption INIT fail")
			}
			
			let updateCheck = EVP_EncryptUpdate(ctx, &resultData, resultSize, dataPointer, Int32(data.count))
			if updateCheck == 0 {
				throw CipherGeneralError.cipherProcessFail(reason: "Encryption UPDATE fail")
			}
			
			let finalCheck = EVP_EncryptFinal(ctx, &resultData, resultSize)
			if finalCheck == 0 {
				throw CipherGeneralError.cipherProcessFail(reason: "Encryption FINAL fail")
			}
			
			let result = Data(resultData)
		
			return result
		}
		
		throw AESError.noInitParameters(reason: "Cipher key or initialization vector is not set")
	}
	
	public func decrypt(data: Data) {
//		let dataPointer = UnsafeMutablePointer<UInt8>(mutating: (data as NSData).bytes.bindMemory(to: UInt8.self, capacity: data.count))
//		let ctx = EVP_CIPHER_CTX_new()
//		
//		let keyPointer = UnsafeMutablePointer<UInt8>(mutating: (key! as NSData).bytes.bindMemory(to: UInt8.self, capacity: key!.count))
//		let ivPointer = UnsafeMutablePointer<UInt8>(mutating: (iv! as NSData).bytes.bindMemory(to: UInt8.self, capacity: iv!.count))
//		
//		var resultData = [UInt8](repeating: UInt8(), count: 32)
//		let resultSize = UnsafeMutablePointer<Int32>.allocate(capacity: MemoryLayout<Int32.Stride>.size)
		
//		EVP_DecryptInit(ctx, self.aesCipher, keyPointer, ivPointer)
//		EVP_DecryptUpdate(ctx, resultData, resultSize, dataPointer, Int32(data.count))
//		EVP_DecryptFinal(<#T##ctx: UnsafeMutablePointer<EVP_CIPHER_CTX>!##UnsafeMutablePointer<EVP_CIPHER_CTX>!#>, <#T##outm: UnsafeMutablePointer<UInt8>!##UnsafeMutablePointer<UInt8>!#>, <#T##outl: UnsafeMutablePointer<Int32>!##UnsafeMutablePointer<Int32>!#>)
	}
	
	//MARK: Private funcs
	
	fileprivate func decideAESCipher() {
		if let keySize = key?.count, let bcm = blockMode {
			if AESKeySize.isAES128(keySize: keySize) && BlockCipherMode.isBlockModeCBC(blockMode: bcm) {
				aesCipher = EVP_aes_128_cbc()
			}
			else if AESKeySize.isAES128(keySize: keySize) && BlockCipherMode.isBlockModeECB(blockMode: bcm) {
				aesCipher = EVP_aes_128_ecb()
			}
			else if AESKeySize.isAES128(keySize: keySize) && BlockCipherMode.isBlockModeCFB(blockMode: bcm) {
				aesCipher = EVP_aes_128_cfb1()
			}
			else if AESKeySize.isAES128(keySize: keySize) && BlockCipherMode.isBlockModeOFB(blockMode: bcm) {
				aesCipher = EVP_aes_128_ofb()
			}
			else if AESKeySize.isAES128(keySize: keySize) && BlockCipherMode.isBlockModeCTR(blockMode: bcm) {
				aesCipher = EVP_aes_128_ctr()
			}
			else if AESKeySize.isAES256(keySize: keySize) && BlockCipherMode.isBlockModeCBC(blockMode: bcm) {
				aesCipher = EVP_aes_256_cbc()
			}
			else if AESKeySize.isAES256(keySize: keySize) && BlockCipherMode.isBlockModeECB(blockMode: bcm) {
				aesCipher = EVP_aes_256_ecb()
			}
			else if AESKeySize.isAES256(keySize: keySize) && BlockCipherMode.isBlockModeCFB(blockMode: bcm) {
				aesCipher = EVP_aes_256_cfb1()
			}
			else if AESKeySize.isAES256(keySize: keySize) && BlockCipherMode.isBlockModeOFB(blockMode: bcm) {
				aesCipher = EVP_aes_256_ofb()
			}
			else if AESKeySize.isAES256(keySize: keySize) && BlockCipherMode.isBlockModeCTR(blockMode: bcm) {
				aesCipher = EVP_aes_256_ctr()
			}
			else if AESKeySize.isAES192(keySize: keySize) && BlockCipherMode.isBlockModeCBC(blockMode: bcm) {
				aesCipher = EVP_aes_192_cbc()
			}
			else if AESKeySize.isAES192(keySize: keySize) && BlockCipherMode.isBlockModeECB(blockMode: bcm) {
				aesCipher = EVP_aes_192_ecb()
			}
			else if AESKeySize.isAES192(keySize: keySize) && BlockCipherMode.isBlockModeCFB(blockMode: bcm) {
				aesCipher = EVP_aes_192_cfb1()
			}
			else if AESKeySize.isAES192(keySize: keySize) && BlockCipherMode.isBlockModeOFB(blockMode: bcm) {
				aesCipher = EVP_aes_192_ofb()
			}
			else if AESKeySize.isAES192(keySize: keySize) && BlockCipherMode.isBlockModeCTR(blockMode: bcm) {
				aesCipher = EVP_aes_192_ctr()
			}
		}
	}
	
	fileprivate func isValid(cipherKey key: Data) -> Bool {
		if let _ = AESKeySize(rawValue: key.count) { return true}
		return false
	}
}
