//
//  Protocols.swift
//  CryptoLab
//
//  Created by Branko Popovic on 3/14/17.
//  Copyright © 2017 Branko Popovic. All rights reserved.
//

import Foundation

/**
Protocol for ciphers that work with single data chunk
*/
public protocol Cryptor {
	/**
	Encrypts data.
	
	- parameter dataToEncrypt: Data to encrypt
	
	- returns: Encrypted data
	*/
	func encrypt(data dataToEncrypt: Data) throws -> Data
	
	/**
	Decrypts data.
	
	- parameter dataToDecrypt: Data to decrypt
	
	- returns: Decrypted data
	*/
	func decrypt(data dataToDecrypt: Data) throws -> Data
}

/**
Protocol for ciphers that work with multiple data chunks
*/
public protocol BlockCryptor: Cryptor {
	/**
	Updates current encrypted data with new data. 
	
	- parameter data: New data to encrypt
	*/
	func updateEncryption(withDataBlock data: Data) throws
	/**
	Finishes encryption process of all data added using updateEncryption function
	
	- returns: Final encrypted data
	*/
	func finishEncryption() throws -> Data
	
	/**
	Updates current decrypted data with new data.
	
	- parameter data: New data to decrypt
	*/
	func updateDecryption(withDataBlock data: Data) throws
	/**
	Finishes decryption process of all data added using updateDecryption function
	
	- returns: Final decrypted data
	*/
	func finishDecryption() throws -> Data
}
