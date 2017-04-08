//
//  HashFunctions.swift
//  CryptoLab
//
//  Created by Branko Popovic on 2/4/17.
//  Copyright © 2017 Branko Popovic. All rights reserved.
//

import Foundation


protocol CoreHashUser {
	var coreHash: CoreHashingFunction {set get}
}

public protocol HashingFunction {
	func hash(data dataToHash: Data) -> Data
	func update(withData data: Data)
	func finishBlock() -> Data
}

extension HashingFunction {
	/**
	Hash data
	
	- parameter dataToHash: Data to hash
	
	- returns: Hashed data
	*/
	public func hash(data dataToHash: Data) -> Data {
		return (self as! CoreHashUser).coreHash.hash(data: dataToHash)
	}
	
	/**
	Updates current data with new data
	
	- parameter data: New data
	*/
	public func update(withData data: Data) {
		return (self as! CoreHashUser).coreHash.update(withData: data)
	}
	
	/**
	Finishes hashing of all data added with update function
	
	- returns: Hashed data
	*/
	public func finishBlock() -> Data {
		return (self as! CoreHashUser).coreHash.finishBlock()
	}
}

public class MD5Hash: NSObject, HashingFunction, CoreHashUser {
	var coreHash: CoreHashingFunction
	
	/**
	New MD5 hashing object
	*/
	override public init() {
		coreHash = MD5CoreHash()
		super.init()
	}
}

public class SHA1Hash: NSObject, HashingFunction, CoreHashUser {
	var coreHash: CoreHashingFunction
	
	/**
	New SHA1 hashing object
	*/
	override public init() {
		coreHash = SHA1CoreHash()
		super.init()
	}
}

public class SHA224Hash: NSObject, HashingFunction, CoreHashUser {
	var coreHash: CoreHashingFunction
	
	/**
	New SHA224 hashing object
	*/
	override public init() {
		coreHash = SHA224CoreHash()
		super.init()
	}
}

public class SHA256Hash: NSObject, HashingFunction, CoreHashUser {
	var coreHash: CoreHashingFunction
	
	/**
	New SHA256 hashing object
	*/
	override public init() {
		coreHash = SHA256CoreHash()
		super.init()
	}
}

public class SHA384Hash: NSObject, HashingFunction, CoreHashUser {
	var coreHash: CoreHashingFunction
	
	/**
	New SHA384 hashing object
	*/
	override public init() {
		coreHash = SHA384CoreHash()
		super.init()
	}
}

public class SHA512Hash: NSObject, HashingFunction, CoreHashUser {
	var coreHash: CoreHashingFunction
	
	/**
	New SHA512 hashing object
	*/
	override public init() {
		coreHash = SHA512CoreHash()
		super.init()
	}
}
