//
//  DH.swift
//  CryptoLab
//
//  Created by Branko Popovic on 4/3/17.
//  Copyright © 2017 Branko Popovic. All rights reserved.
//

import Foundation
import OpenSSL

/**
Diffie-Hellman key exchange class
*/
public class DiffieHellman: NSObject {
	private let dhCore: DiffieHellmanCore
	
	/** 
	Prime number (shared) (get only)
	*/
	public var p: String? { return dhCore.p }
	
	/**
	Generator of Z_p (shared) (get only)
	*/
	public var g: String? { return dhCore.g }
	
	/**
	Public DH value g^x (get only)
	*/
	public var publicKey: String? {return dhCore.publicKey }
	
	/**
	Creates new DiffieHellman object with custom prime and generator
	
	- parameter p: Prime number
	- parameter g: Generator
	*/
	public init(p: String, g: String) {
		dhCore = DiffieHellmanCore(p: p, g: g)
		super.init()
	}
	
	/**
	Creates new DiffieHellman object. Generetes prime number of given length.
	
	- parameter primeLength: Length of prime that will be generated
	*/
	public init(primeLength: Int) {
		dhCore = DiffieHellmanCore(primeLength: primeLength)
		super.init()
	}
	
	/**
	Computes shared secret with public key.
	
	- parameter publicKey: Public key of other client.
	*/
	public func computeSharedSecret(withPublicKey publicKey: Data) -> Data? {
		return dhCore.computeKey(withPublicKey: publicKey)
	}
	
}
