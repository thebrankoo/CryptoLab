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

/**
Protocol with default hash function implementation
*/
public protocol HashingFunction {
	/**
	Hash data
	
	- parameter dataToHash: Data to hash
	
	- returns: Hashed data
	*/
	func hash(data dataToHash: Data) -> Data
	
	/**
	Updates current data with new data
	
	- parameter data: New data
	*/
	func update(withData data: Data)
	
	/**
	Finishes hashing of all data added with update function
	
	- returns: Hashed data
	*/
	func finishBlock() -> Data
}

extension HashingFunction {
	public func hash(data dataToHash: Data) -> Data {
		return (self as! CoreHashUser).coreHash.hash(data: dataToHash)
	}
	
	public func update(withData data: Data) {
		return (self as! CoreHashUser).coreHash.update(withData: data)
	}
	
	public func finishBlock() -> Data {
		return (self as! CoreHashUser).coreHash.finishBlock()
	}
}

/**
MD5 hash class (check protocols it implements)
*/
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

/**
SHA1 hash class (check protocols it implements)
*/
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

/**
SHA224 hash class (check protocols it implements)
*/
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

/**
SHA256 hash class (check protocols it implements)
*/
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

/**
SHA384 hash class (check protocols it implements)
*/
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

/**
SHA512 hash class (check protocols it implements)
*/
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
