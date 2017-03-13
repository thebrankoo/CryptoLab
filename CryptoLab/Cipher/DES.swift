//
//  DES.swift
//  CryptoLab
//
//  Created by Branko Popovic on 3/7/17.
//  Copyright © 2017 Branko Popovic. All rights reserved.
//

import Foundation
import OpenSSL

public enum DESBlockCipherMode {
	case ecb
	case ede
	case ede3
	case cfb64
	case cfb1
	case cfb8
	case ofb
	case cbc
	
	func blockMode() -> UnsafePointer<EVP_CIPHER> {
		switch self {
		case .ecb:
			return EVP_des_ecb()
		case .ede:
			return EVP_des_ede()
		case .ede3:
			return EVP_des_ede3()
		case .cfb64:
			return EVP_des_cfb64()
		case .cfb1:
			return EVP_des_cfb1()
		case .cfb8:
			return EVP_des_cfb8()
		case .ofb:
			return EVP_des_ofb()
		case .cbc:
			return EVP_des_cbc()
		}
	}
}

public class DESCoreCipher: NSObject {
	static let ivSize = 16
	fileprivate let key: Data?
	fileprivate let iv: Data?
	
	private let blockMode: DESBlockCipherMode?
	private var desCipher: UnsafePointer<EVP_CIPHER>? {
		return blockMode?.blockMode()
	}
	private var context: UnsafeMutablePointer<EVP_CIPHER_CTX>?
	
	private var decContext: UnsafeMutablePointer<EVP_CIPHER_CTX>?
	
	
	public init(key: Data, iv: Data, blockMode: DESBlockCipherMode) throws {
		self.key = key
		self.iv = iv
		self.blockMode = blockMode
		super.init()
	}
	
	public func encrypt(data: Data) throws -> Data {
		
		do {
			try updateEncryption(data: data)
			let finalData = try finishEncryption()
			return finalData
		}
		catch {
			throw CipherError.cipherProcessFail(reason: CipherErrorReason.cipherFinish)
		}
	}
	
	public func decrypt(data: Data) throws -> Data {
		
		if let iv = self.iv, let key = self.key {
			do {
				try initDecryption(withKey: key, andIV: iv)
				try updateDecryption(withData: data)
				let finishData = try finishDecryption()
				return finishData
			}
			catch let error {
				throw error
			}
		}
		else {
			throw CipherError.cipherProcessFail(reason: "Decrypt AES No key or iv")
		}
	}
	
	//MARK: Encryption
	
	fileprivate func initEncryption(withKey key: Data, andIV iv: Data) throws {
		self.context = EVP_CIPHER_CTX_new()
		
		let keyPointer = UnsafeMutablePointer<UInt8>(mutating: (key as NSData).bytes.bindMemory(to: UInt8.self, capacity: key.count))
		let ivPointer = UnsafeMutablePointer<UInt8>(mutating: (iv as NSData).bytes.bindMemory(to: UInt8.self, capacity: iv.count))
		let initCheck = EVP_EncryptInit(context!, self.desCipher, keyPointer, ivPointer)
		if initCheck == 0 {
			throw CipherError.cipherProcessFail(reason: CipherErrorReason.cipherInit)
		}
	}
	
	fileprivate func updateEncryption(data toUpdate: Data) throws {
		if let key = key, let iv = iv {
			
			let dataPointer = UnsafeMutablePointer<UInt8>(mutating: (toUpdate as NSData).bytes.bindMemory(to: UInt8.self, capacity: toUpdate.count))
			
			if !isUpdateInProcess() {
				do {
					try initEncryption(withKey: key, andIV: iv)
				}
				catch let error {
					throw error
				}
			}
			
			if let ctx = context {
				var resultData = [UInt8](repeating: UInt8(), count: key.count)
				let resultSize = UnsafeMutablePointer<Int32>.allocate(capacity: MemoryLayout<Int32.Stride>.size)
				
				let updateCheck = EVP_EncryptUpdate(ctx, &resultData, resultSize, dataPointer, Int32(toUpdate.count))
				if updateCheck == 0 {
					throw CipherError.cipherProcessFail(reason: CipherErrorReason.cipherUpdate)
				}
			}
			
		}
	}

	fileprivate func finishEncryption() throws -> Data {
		if let ctx = context, let key = key {
			var resultData = [UInt8](repeating: UInt8(), count: key.count)
			let resultSize = UnsafeMutablePointer<Int32>.allocate(capacity: MemoryLayout<Int32.Stride>.size)
			let finalCheck = EVP_EncryptFinal(ctx, &resultData, resultSize)
			if finalCheck == 0 {
				throw CipherError.cipherProcessFail(reason: CipherErrorReason.cipherFinish)
			}
			
			let result = Data(resultData)
			EVP_CIPHER_CTX_cleanup(self.context)
			self.context = nil
			return result
		}
		else {
			throw CipherError.cipherProcessFail(reason: "Encryption invalid or missing parameters")
		}
	}
	
	//MARK: Decryption
	
	fileprivate var decryptionResultSize: Int32 = 0
	
	fileprivate func initDecryption(withKey key: Data, andIV iv: Data) throws {
		
		self.decContext = EVP_CIPHER_CTX_new()
		
		let keyPointer = UnsafeMutablePointer<UInt8>(mutating: (key as NSData).bytes.bindMemory(to: UInt8.self, capacity: key.count))
		let ivPointer = UnsafeMutablePointer<UInt8>(mutating: (iv as NSData).bytes.bindMemory(to: UInt8.self, capacity: iv.count))
		
		let initStatus = EVP_DecryptInit(self.decContext!, self.desCipher, keyPointer, ivPointer)
		if initStatus == 0 {
			throw CipherError.cipherProcessFail(reason: CipherErrorReason.cipherInit)
		}
	}
	
	fileprivate func updateDecryption(withData data: Data) throws {
		let dataPointer = UnsafeMutablePointer<UInt8>(mutating: (data as NSData).bytes.bindMemory(to: UInt8.self, capacity: data.count))
		
		var resultData = [UInt8](repeating: UInt8(), count: 32)
		let resultSize = UnsafeMutablePointer<Int32>.allocate(capacity: MemoryLayout<Int32.Stride>.size)
		
		if let ctx = self.decContext {
			let updateStatus = EVP_DecryptUpdate(ctx, &resultData, resultSize, dataPointer, Int32(data.count))
			decryptionResultSize += resultSize.pointee
			if updateStatus == 0 {
				throw CipherError.cipherProcessFail(reason: CipherErrorReason.cipherUpdate)
			}
		}
	}
	
	fileprivate func finishDecryption() throws -> Data {
		
		if let ctx = decContext {
			var resultData = [UInt8]()
			let resultSize = UnsafeMutablePointer<Int32>.allocate(capacity: MemoryLayout<Int32.Stride>.size)
			var finishStatus = EVP_DecryptFinal_ex(ctx, &resultData, resultSize) //EVP_DecryptFinal(ctx, &resultData, resultSize)
			
			if finishStatus == 1 {
				resultData = [UInt8](repeating: UInt8(), count: Int(resultSize.pointee))
				finishStatus = EVP_DecryptFinal_ex(ctx, &resultData, resultSize)
				
				if finishStatus == 0 {
					throw CipherError.cipherProcessFail(reason: CipherErrorReason.cipherFinish)
				}
			}
			self.context = nil
			return Data(resultData)
		}
		else {
			throw CipherError.cipherProcessFail(reason: CipherErrorReason.cipherFinish)
		}
	}

	
	
	fileprivate func isUpdateInProcess() -> Bool {
		if let _  = context {return true}
		return false
	}
}

