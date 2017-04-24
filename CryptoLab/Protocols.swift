//
//  Protocols.swift
//  CryptoLab
//
//  Created by Branko Popovic on 3/14/17.
//  Copyright © 2017 Branko Popovic. All rights reserved.
//

import Foundation

public protocol CoreCryptor {
	func encrypt(data toEncrypt: Data) throws -> Data
	func decrypt(data toDecrypt: Data) throws -> Data
}

public protocol CoreBlockCryptor: CoreCryptor {
	func initEncryption(withKey key: Data, andIV iv: Data) throws
	func updateEncryption(data toUpdate: Data) throws
	func finishEncryption() throws -> Data
	
	func initDecryption(withKey key: Data, andIV iv: Data) throws
	func updateDecryption(withData data: Data) throws
	func finishDecryption() throws -> Data
}


/**
Protocol for ciphers that work with single data chunk
*/
public protocol Cryptor {
	var coreCryptor: CoreCryptor {get}
}

extension Cryptor {
	/**
	Encrypts data.
	
	- parameter dataToEncrypt: Data to encrypt
	
	- returns: Encrypted data
	*/
	public func encrypt(data dataToEncrypt: Data) throws -> Data {
		
		do {
			let encrypted = try self.coreCryptor.encrypt(data: dataToEncrypt)
			return encrypted
		}
		catch let error {
			throw error
		}
	}
	
	/**
	Decrypts data.
	
	- parameter dataToDecrypt: Data to decrypt
	
	- returns: Decrypted data
	*/
	public func decrypt(data dataToDecrypt: Data) throws -> Data {
		do {
			let decrypted = try self.coreCryptor.decrypt(data: dataToDecrypt)
			return decrypted
		}
		catch let error {
			throw error
		}
	}
}

/**
Protocol for ciphers that work with multiple data chunks
*/
public protocol BlockCryptor: Cryptor {
}

extension BlockCryptor {
	/**
	Updates current encrypted data with new data. 
	
	- parameter data: New data to encrypt
	*/
	public func updateEncryption(withDataBlock data: Data) throws {
		do {
			try (coreCryptor as! CoreBlockCryptor).updateEncryption(data: data)
		}
		catch let error {
			throw error
		}
	}
	/**
	Finishes encryption process of all data added using updateEncryption function
	
	- returns: Final encrypted data
	*/
	public func finishEncryption() throws -> Data {
		do {
			let finalData = try (coreCryptor as! CoreBlockCryptor).finishEncryption()
			return finalData
		}
		catch let error{
			throw error
		}
	}
	
	/**
	Updates current decrypted data with new data.
	
	- parameter data: New data to decrypt
	*/
	public func updateDecryption(withDataBlock data: Data) throws {
		do {
			try (coreCryptor as! CoreBlockCryptor).updateDecryption(withData: data)
		}
		catch let err {
			throw err
		}
	}
	/**
	Finishes decryption process of all data added using updateDecryption function
	
	- returns: Final decrypted data
	*/
	public func finishDecryption() throws -> Data {
		do {
			let finished = try (coreCryptor as! CoreBlockCryptor).finishDecryption()
			return finished
		}
		catch let err {
			throw err
		}
	}
}
