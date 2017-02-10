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

public class AESCipher: NSObject {
	static let ivSize = 16
	let key: Data?
	let iv: Data?
	let blockMode: BlockCipherMode?
	
	fileprivate var aesCipher: UnsafePointer<EVP_CIPHER>?
	
	public init(key: Data, iv: Data, blockMode: BlockCipherMode) {
		self.key = key
		self.iv = iv
		self.blockMode = blockMode
		
		super.init()
	}
	
	public func encrypt() {
		
	}
	
	public func decrypt() {
		
	}
	
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
}

public class GeneralCipher: NSObject {
	
	public func testCipher() -> Data  {
		let ctx = EVP_CIPHER_CTX_new()
		
		let keydata = "testkey".data(using: .utf8)!
		let keydataPointer = UnsafeMutablePointer<UInt8>(mutating: (keydata as NSData).bytes.bindMemory(to: UInt8.self, capacity: keydata.count))
		
		let ivdata = "randomIvData".data(using: .utf8)!
		let ivdataPointer = UnsafeMutablePointer<UInt8>(mutating: (ivdata as NSData).bytes.bindMemory(to: UInt8.self, capacity: ivdata.count))
		
		let encData = "Test Enc String".data(using: .utf8)!
		let encDataPointer = UnsafeMutablePointer<UInt8>(mutating: (encData as NSData).bytes.bindMemory(to: UInt8.self, capacity: encData.count))
		
		var resultData = [UInt8](repeating: UInt8(), count: Int(16))
		let resultSize = UnsafeMutablePointer<Int32>.allocate(capacity: MemoryLayout<Int32.Stride>.size)

		
		
		let evpCipher = EVP_aes_128_cbc()!
		
		EVP_EncryptInit(ctx, evpCipher, keydataPointer, ivdataPointer)
		EVP_EncryptUpdate(ctx, &resultData, resultSize, encDataPointer, Int32(encData.count))
		EVP_EncryptFinal(ctx, &resultData, resultSize)
		
		let result = Data(resultData)
		
		return result
	}
	
}
