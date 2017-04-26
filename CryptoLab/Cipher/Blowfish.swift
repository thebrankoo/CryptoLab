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
Blowfish encryption/decryption class
*/
public class BlowfishCipher: NSObject, Cryptor {
	public var coreCryptor: CoreCryptor
	
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
		coreCryptor = BlowfishCoreCipher(key: key, iv: iv, encryptionMode: encryptionMode)
		self.key = key
		super.init()
	}
}

