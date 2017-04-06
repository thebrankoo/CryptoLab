//
//  Extensions.swift
//  CryptoLab
//
//  Created by Branko Popovic on 2/25/17.
//  Copyright © 2017 Branko Popovic. All rights reserved.
//

import Foundation

extension Data {
	
	static func makeUInt8EmptyArray(ofSize size: Int) -> [UInt8] {
		return [UInt8](repeating: UInt8(), count: size)
	}
	
	func makeUInt8DataPointer() -> UnsafeMutablePointer<UInt8> {
		let dataPointer = UnsafeMutablePointer<UInt8>(mutating: (self as NSData).bytes.bindMemory(to: UInt8.self, capacity: self.count))
		return dataPointer
	}
	
	func makeInt8DataPointer() -> UnsafeMutablePointer<Int8> {
		let dataPointer = UnsafeMutablePointer<Int8>(mutating: (self as NSData).bytes.bindMemory(to: Int8.self, capacity: self.count))
		return dataPointer
	}
	
	public func hexEncodedString() -> String {
		return map { String(format: "%02hhx", $0) }.joined()
	}
}
