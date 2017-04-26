//
//  RSA.swift
//  CryptoLab
//
//  Created by Branko Popovic on 2/11/17.
//  Copyright © 2017 Branko Popovic. All rights reserved.
//

import Foundation
import OpenSSL

/**
RSA encryption/decryption and sign/verifiy class.
*/
public class RSACipher: NSObject, Cryptor {
	
	public var coreCryptor: CoreCryptor
	
	/**
	RSA private key (get only)
	*/
	public var privateKey: String? {
		return (coreCryptor as? RSACoreCipher)?.privateKey
	}
	
	/**
	RSA public key (get only)
	*/
	public var publicKey: String? {
		return (coreCryptor as? RSACoreCipher)?.publicKey
	}
	
	/**
	Creates new RSACipher object using desired padding (set to none if not specified).
	
	- parameter padding: RSA padding. Default value is none.
	*/
	public init(padding: RSAPadding = .none) {
		coreCryptor = RSACoreCipher(padding: padding)
		super.init()
	}
	
	/**
	Creates new RSACipher object using public key and padding (set to none if not specified).
	
	- parameter publicKey: RSA public key
	- parameter padding: RSA padding. Default value is none.
	*/
	public init(publicKey: Data, padding: RSAPadding = .none) {
		coreCryptor = RSACoreCipher(publicKey: publicKey, padding: padding)
		super.init()
	}
	
	/**
	Creates new RSACipher object using public key, private key and padding (set to none if not specified).
	
	- parameter publicKey: RSA public key
	- parameter privateKey: RSA private key
	- parameter padding: RSA padding. Default value is none.
	*/
	public init(publicKey: Data, privateKey: Data, padding: RSAPadding = .none) {
		coreCryptor = RSACoreCipher(publicKey: publicKey, privateKey: privateKey, padding: padding)
		super.init()
	}
}

public class RSASignature: NSObject, SignVerifier {
	public var signVerifier: CoreSignVerifier
	
	public init(type: RSASignatureType) {
		signVerifier = CoreRSASignVerifier(type: type)
		super.init()
	}
	
	public init(publicKey: Data, type: RSASignatureType) {
		signVerifier = CoreRSASignVerifier(publicKey: publicKey, type: type)
		super.init()
	}
	
	public init(publicKey: Data, privateKey: Data, type: RSASignatureType) {
		signVerifier = CoreRSASignVerifier(publicKey: publicKey, privateKey: privateKey, type: type)
		super.init()
	}
}
