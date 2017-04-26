//
//  Protocols.swift
//  CryptoLab
//
//  Created by Branko Popovic on 3/14/17.
//  Copyright © 2017 Branko Popovic. All rights reserved.
//

import Foundation

/**
Provides core crypting interface (for abstraction use Cryptor protocol)
*/
public protocol CoreCryptor {
	/**
	Encrypts data and throws error if needed
	
	- parameter toEncrypt: Data to encrypt
	*/
	func encrypt(data toEncrypt: Data) throws -> Data
	
	/**
	Decrypts data and throws error if needed
	
	- parameter toDecrypt: Data to encrypt
	*/
	func decrypt(data toDecrypt: Data) throws -> Data
}

/**
Provides core crypting interface for block encryption/decryption (for abstraction use BlockCryptor protocol)
*/
public protocol CoreBlockCryptor: CoreCryptor {
	/**
	Inits new block encryption and throws error if needed
	
	- parameter key: Encryption key
	- parameter iv: Initialization vector
	*/
	func initEncryption(withKey key: Data, andIV iv: Data) throws
	
	/**
	Updates new block encryption and throws error if needed
	
	- parameter data: Data block to update encryption with
	- parameter iv: Initialization vector
	*/
	func updateEncryption(data toUpdate: Data) throws
	
	/**
	Finishes block encryption and throws error if needed
	
	- returns: Encrypted data
	*/
	func finishEncryption() throws -> Data
	
	/**
	Inits new block decryption and throws error if needed
	
	- parameter key: Decryption key
	- parameter iv: Initialization vector
	*/
	func initDecryption(withKey key: Data, andIV iv: Data) throws
	
	/**
	Updates new block encryption and throws error if needed
	
	- parameter key: Data block to update decryption with
	*/
	func updateDecryption(withData data: Data) throws
	
	/**
	Finishes block decryption and throws error if needed
	
	- returns: Decrypted data
	*/
	func finishDecryption() throws -> Data
}

/**
Provides core interface for message sign/verify (for abstraction use SignVerifier protocol)
*/
public protocol CoreSignVerifier {
	/**
	Sign message data
	
	- parameter toSign: Data to sign
	
	- returns: Data signature
	*/
	func sign(data toSign: Data) -> Data?
	
	/**
	Verify message signature
	
	- paramter toVerify: Digest data 
	- paramter signature: Original signature
	
	- returns: True if verification success, false otherwise
	*/
	func verify(data toVerify: Data, signature: Data) -> Bool
}

/**
Provides interface for message sign/verify
*/
public protocol SignVerifier {
	/**
	Internal object
	*/
	var signVerifier: CoreSignVerifier {get}
}

extension SignVerifier {
	/**
	Signs data using the private key
	
	- parameter toSign: Data to sign
	- parameter type: Message digest algorithm
	*/
	public func sign(data toSign: Data) -> Data? {
		return signVerifier.sign(data: toSign)
	}
	/**
	Verifies data metches given signature
 
	- parameter toVerify: Data to verify
	- parameter signature: Given signature
	- parameter type: Message digest algorithm
	*/
	public func verify(data toVerify: Data, signature: Data) -> Bool {
		return signVerifier.verify(data: toVerify, signature: signature)
	}
}

/**
Protocol for ciphers that work with single data chunk
*/
public protocol Cryptor {
	/**
	Internal object
	*/
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
