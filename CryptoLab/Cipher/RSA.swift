//
//  RSA.swift
//  CryptoLab
//
//  Created by Branko Popovic on 2/11/17.
//  Copyright © 2017 Branko Popovic. All rights reserved.
//

import Foundation
import OpenSSL

public enum RSAPadding {
	case pkcs1 //PKCS #1 v1.5 padding
	case pkcs1_oaep //EME-OAEP as defined in PKCS #1 v2.0 with SHA-1, MGF1 and an empty encoding parameter
	case sslv23 //PKCS #1 v1.5 padding with an SSL-specific modification that denotes that the server is SSL3 capable
	case none //Raw RSA encryption
	
	fileprivate func openSSLPadding() -> Int32 {
		switch self {
		case .pkcs1:
			return RSA_PKCS1_PADDING
		case .pkcs1_oaep:
			return RSA_PKCS1_OAEP_PADDING
		case .sslv23:
			return RSA_SSLV23_PADDING
		case .none:
			return RSA_NO_PADDING
		}
	}
}

public class RSACipher: NSObject {
	
	private let coreCipher: RSACoreCipher?
	
	public var privateKey: String? {
		return coreCipher?.privateKey
	}
	public var publicKey: String? {
		return coreCipher?.publicKey
	}
	
	public init(padding: RSAPadding = .none) {
		coreCipher = RSACoreCipher(padding: padding)
		super.init()
	}
	
	public init(publicKey: Data, padding: RSAPadding = .none) {
		coreCipher = RSACoreCipher(publicKey: publicKey, padding: padding)
		super.init()
	}
	
	public init(publicKey: Data, privateKey: Data, padding: RSAPadding = .none) {
		coreCipher = RSACoreCipher(publicKey: publicKey, privateKey: privateKey, padding: padding)
		super.init()
	}
	
	public func encrypt(data dataToEncrypt: Data) -> Data? {
		let finalData = coreCipher?.encrypt(data: dataToEncrypt)
		return finalData
	}
	
	public func decrypt(data dataToDecrypt: Data) -> Data? {
		let finalData = coreCipher?.decrypt(data: dataToDecrypt)
		return finalData
	}
}

class RSACoreCipher: NSObject {
	
	private let keychain: RSAKeychain?
	private let padding: Int32
	
	
	var privateKey: String? {
		return keychain?.privateKey
	}
	
	var publicKey: String? {
		return keychain?.publicKey
	}
	
	public init(padding: RSAPadding = .none) {
		keychain = RSAKeychain()
		self.padding = padding.openSSLPadding()
		
		super.init()
	}
	
	public init(publicKey: Data, padding: RSAPadding = .none) {
		keychain = RSAKeychain(publicKey: publicKey)
		self.padding = padding.openSSLPadding()
		
		super.init()
	}
	
	public init(publicKey: Data, privateKey: Data, padding: RSAPadding = .none) {
		keychain = RSAKeychain(publicKey: publicKey, privateKey: privateKey)
		self.padding = padding.openSSLPadding()
		
		super.init()
	}
	
	//MARK: Core Cipher Interface
	
	func encrypt(data dataToEncode: Data) -> Data? {
		if let rsaKey = self.keychain?.rsaKeyPair {
			return encrypt(data: dataToEncode, rsaKey: rsaKey)
		}
		return nil
	}
	
	func decrypt(data dataToDecode:Data) -> Data? {
		if let rsaKey = self.keychain?.rsaKeyPair {
			return decrypt(data: dataToDecode, rsaKey: rsaKey)
		}
		return nil
	}
	
	//MARK: Core Cipher privates
	
	private func encrypt(data dataToEncode: Data, rsaKey: UnsafeMutablePointer<RSA>) -> Data? {
		let rsaStruct =  UnsafeMutablePointer(rsaKey)
		
		let dataPointer = (dataToEncode as NSData).bytes.bindMemory(to: UInt8.self, capacity: dataToEncode.count)
		let dataSize = dataToEncode.count
		
		let encryptedPointer = UnsafeMutablePointer<UInt8>.allocate(capacity: Int(RSA_size(rsaStruct)))
		
		let encryptedSize = RSA_public_encrypt(Int32(dataSize), dataPointer, encryptedPointer, rsaStruct, padding)
		
		if encryptedSize == -1 {
			//printCryptoError()
			return nil
		}
		
		return Data(bytes: UnsafePointer<UInt8>(encryptedPointer), count: Int(encryptedSize))
	}
	
	private func decrypt(data dataToDecode:Data, rsaKey: UnsafeMutablePointer<RSA>) -> Data? {
		let rsaStruct = rsaKey
		let dataPointer = (dataToDecode as NSData).bytes.bindMemory(to: UInt8.self, capacity: dataToDecode.count)
		let dataSize = 4098 //dataToDecode.count
		let decryptedPointer = UnsafeMutablePointer<UInt8>.allocate(capacity: dataSize)
		
		let decryptedSize = RSA_private_decrypt(Int32(dataSize), dataPointer, decryptedPointer, rsaStruct, padding)
		
		if decryptedSize == -1 {
			//printCryptoError()
			return nil
		}
		
		return Data(bytes: UnsafePointer<UInt8>(decryptedPointer), count: Int(decryptedSize))
	}
}

class RSAKeychain: NSObject {
	
	var rsaKeyPair: UnsafeMutablePointer<RSA>? = RSA_new()
	
	var publicKey: String? {
		if let _ = rsaKeyPair {
			let publicKey = extractPublicKeyFromRSAKeyPair()
			
			return publicKey
		}
		return nil
	}
	
	var privateKey: String? {
		if let _ = rsaKeyPair {
			let privateKey = extractPrivateKeyFromRSAKeyPair()
			return privateKey
		}
		return nil
	}
	
	
	override init() {
		super.init()
		rsaKeyPair = generateRandomRSAKey()
	}
	
	init(publicKey: Data) {
		super.init()
		rsaKeyPair = rsaKey(fromPublicKeyString: publicKey)
	}
	
	init(publicKey: Data, privateKey: Data) {
		super.init()
		rsaKeyPair = rsaKey(fromPublicKeyString: publicKey, andPrivateKeyString: privateKey)
	}
	
	//MARK: RSA Key Generators
	
	fileprivate func generateRandomRSAKey() -> UnsafeMutablePointer<RSA>? {
		
		let rsaStruct : UnsafeMutablePointer<RSA> = RSA_new()
		
		let bigStruct : UnsafeMutablePointer<BIGNUM> = BN_new()
		
		BN_set_word(bigStruct, 65537)
		
		RSA_generate_key_ex(rsaStruct, Int32(2048), bigStruct, nil)
		
		return rsaStruct
	}
	
	fileprivate func rsaKey(fromPublicKeyString publicKey: Data, andPrivateKeyString privateKey: Data) -> UnsafeMutablePointer<RSA>?{
		
		let rsaK = rsaKey(fromPublicKeyString: publicKey)
		
		let rsaKeyPointer = UnsafeMutablePointer<UnsafeMutablePointer<RSA>>.allocate(capacity: 256)
		rsaKeyPointer.initialize(to: rsaK)
		
		let bioStruct : UnsafeMutablePointer<BIO> = BIO_new(BIO_s_mem())
		
		let data = privateKey
		
		BIO_write(bioStruct, ((data as NSData?)?.bytes)!, Int32(data.count))
		
		let rsaNew = PEM_read_bio_RSAPrivateKey(bioStruct, nil /*rsaKeyPointer*/, nil, nil)
		
		BIO_free(bioStruct)
		
		return rsaNew
	}
	
	fileprivate func rsaKey(fromPublicKeyString pubKey: Data) -> UnsafeMutablePointer<RSA> {
		
		let bioStruct : UnsafeMutablePointer<BIO> = BIO_new(BIO_s_mem())
		
		let data = pubKey
		
		BIO_write(bioStruct, ((data as NSData?)?.bytes)!, Int32(data.count))
		
		let rsaPointerPointer = UnsafeMutablePointer<UnsafeMutablePointer<RSA> >.allocate(capacity: 256)
		rsaPointerPointer.initialize(to: RSA_new())
		
		//TODO: Handle NIL rsaNew
		
		let rsaNew = PEM_read_bio_RSAPublicKey(bioStruct, nil, nil, nil)
		
		BIO_free(bioStruct)
		
		return rsaNew!
	}
	
	//MARK: RSA Keys to string
	
	fileprivate func extractPublicKeyFromRSAKeyPair() -> String? {
		
		if let rsaStruct = rsaKeyPair {
			
			
			let bioStruct : UnsafeMutablePointer<BIO> = BIO_new(BIO_s_mem())
			
			let error = PEM_write_bio_RSAPublicKey(bioStruct, rsaStruct)
			
			if error == 0 {
				//logger.debug("PPKey Write RSA error")
				return nil
			}
			
			let size : size_t = BIO_ctrl_pending(bioStruct)
			
			let key =  UnsafeMutablePointer<CChar>.allocate(capacity: size)
			
			//logger.debug("Public BIO size: \(size)")
			
			let priLen = BIO_read(bioStruct, key, Int32(size+1))
			
			BIO_free(bioStruct)
			
			if priLen != Int32(size) {
				//logger.debug("PPKey len diff error")
				return nil
			}
			
			let convertResult = String.init(cString: key)
			
			var trimmedString = convertResult
			
			while true {
				if trimmedString.characters.last == "\n" || trimmedString.characters.last == "-" {
					//let len = trimmedString.lengthOfBytesUsingEncoding(NSUTF8StringEncoding)
					break
					
				}
				else {
					trimmedString.remove(at: trimmedString.characters.index(before: trimmedString.endIndex))
				}
			}
			
			//logger.debug("Final Pub String: \(trimmedString)")
			
			
			
			
			return trimmedString
		}
		
		//logger.debug("RSAKeyPair is nil")
		
		return nil
	}
	
	fileprivate func extractPrivateKeyFromRSAKeyPair() -> String? {
		if let rsaStruct = rsaKeyPair {
			
			let bioStruct : UnsafeMutablePointer<BIO> = BIO_new(BIO_s_mem())
			
			let error = PEM_write_bio_RSAPrivateKey(bioStruct, rsaStruct, nil, nil, 0, nil, nil) //PEM_write_bio_RSAPublicKey(bioStruct, rsaStruct)
			
			if error == 0 {
				//logger.debug("Private Write RSA error")
				return nil
			}
			
			let size : size_t = BIO_ctrl_pending(bioStruct)
			
			//logger.debug("Private BIO size: \(size)")
			
			let key = UnsafeMutablePointer<CChar>.allocate(capacity: size)
			
			let priLen = BIO_read(bioStruct, key, Int32(size+1))
			
			BIO_free(bioStruct)
			
			if priLen != Int32(size) {
				//logger.debug("PPKey len diff error")
				return nil
			}
			//logger.debug("CS String Priv: \(key.pointee) ")
			
			
			let convertResult  = String.init(cString: key)
			
			return convertResult //String.fromCString(key)
		}
		
		//logger.debug("RSAKeyPair is nil")
		
		return nil
	}
	
	fileprivate func printCryptoError(){
		ERR_load_CRYPTO_strings()
		let err = UnsafeMutablePointer<CChar>.allocate(capacity: 130)
		//ERR_error_string(ERR_get_error(), err)
		//logger.debug("ENC ERROR \(String(cString: err))")
		err.deinitialize()
		err.deallocate(capacity: 130)
	}
}
