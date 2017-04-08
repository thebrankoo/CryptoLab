//
//  DH.swift
//  CryptoLab
//
//  Created by Branko Popovic on 4/3/17.
//  Copyright © 2017 Branko Popovic. All rights reserved.
//

import Foundation
import OpenSSL

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

class DiffieHellmanCore: NSObject {
	
	var dhKey: UnsafeMutablePointer<DH>?

	var publicKey: String? {
		return extractPublicKey()
	}
	
	var p: String? {
		return extractParameterP()
	}
	
	var g: String? {
		return extractParameterG()
	}
	
	init(p: String, g: String) {
		super.init()
		generateKey(p: p, g: g)
	}
	
	init(primeLength: Int) {
		super.init()
		dhKey = generateKey(primeLen: primeLength)
	}
	
	func generateKey(p pValue: String, g gValue: String) {
		dhKey = DH_new()
		
		var bnP = BN_new()
		let pData = pValue.data(using: .utf8)?.makeInt8DataPointer()
		let pPointer = UnsafePointer<Int8>(pData)
		BN_dec2bn(&bnP, pPointer!)
		
		var bnG = BN_new()
		let gData = gValue.data(using: .utf8)?.makeInt8DataPointer()
		let gPointer = UnsafePointer<Int8>(gData)
		BN_dec2bn(&bnG, gPointer!)
		
		dhKey!.pointee.p = bnP
		dhKey!.pointee.g = bnG
		
		DH_generate_key(dhKey!)
	}
	
	func generateKey(primeLen len: Int) -> UnsafeMutablePointer<DH>? {
		if let key = DH_generate_parameters(Int32(len), 2, nil, nil) {
			DH_generate_key(key)
			return key
		}
		return nil
	}
	
	func computeKey(withPublicKey pk: Data) -> Data? {
		if let dhKey = dhKey {
			let size = DH_size(dhKey)
			var computedKey = Data.makeUInt8EmptyArray(ofSize: Int(size))
			
			var bnG = BN_new()
			let gData = pk.makeInt8DataPointer()
			let gPointer = UnsafePointer<Int8>(gData)
			BN_dec2bn(&bnG, gPointer)
			
			DH_compute_key(&computedKey, bnG, dhKey)
			return Data(bytes: computedKey)
		}
		return nil
	}
	
	func extractPublicKey() -> String? {
		if let dhKey = dhKey {
			let bnP = dhKey.pointee.pub_key
			
			if let pData = BN_bn2dec(bnP) {
				if let p =  String(utf8String: pData) {
					return String(describing: p)
				}
			}
		}
		return nil
	}
	
	func extractParameterP() -> String? {
		if let dhKey = dhKey {
			let bnP = dhKey.pointee.p
			
			if let pData = BN_bn2dec(bnP) {
				if let p =  String(utf8String: pData) {
					return String(describing: p)
				}
			}
		}
		return nil
	}
	
	func extractParameterG() -> String? {
		if let dhKey = dhKey {
			let bnG = dhKey.pointee.g
			
			if let gData = BN_bn2dec(bnG) {
				if let g =  String(utf8String: gData) {
					return String(describing: g)
				}
			}
		}
		return nil
	}
}
