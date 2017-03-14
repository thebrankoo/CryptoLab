//
//  Protocols.swift
//  CryptoLab
//
//  Created by Branko Popovic on 3/14/17.
//  Copyright © 2017 Branko Popovic. All rights reserved.
//

import Foundation

public protocol Cryptor {
	func encrypt(data dataToEncrypt: Data) throws -> Data
	func decrypt(data dataToDecrypt: Data) throws -> Data
}

public protocol BlockCryptor {
	func updateEncryption(withDataBlock data: Data) throws
	func finishEncryption() throws -> Data
	
	func updateDecryption(withDataBlock data: Data) throws
	func finishDecryption() throws -> Data
}
