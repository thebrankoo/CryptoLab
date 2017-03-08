//
//  DSA.swift
//  CryptoLab
//
//  Created by Branko Popovic on 3/7/17.
//  Copyright © 2017 Branko Popovic. All rights reserved.
//

import Foundation
import OpenSSL

public class DSACore: NSObject {
	
	let key: Data?
	public static var dsaKey: UnsafeMutablePointer<DSA>?
	
	public init(key: Data?) {
		self.key = key
		super.init()
	}
	
	public func generateDSA() {
		DSACore.dsaKey = generateDSAPrivPubKeys(key: generateDSAKeyWithParameters())
	}
	
	func generateDSAPrivPubKeys(key: UnsafeMutablePointer<DSA>?) -> UnsafeMutablePointer<DSA>? {
		
		let dsaError = DSA_generate_key(key)
		
		if dsaError != 1 {
			print("DSA key generate error")
		}
		
		return key
	}
	
	func generateDSAKeyWithParameters() -> UnsafeMutablePointer<DSA>? {
		let bits = 1024
		let des = DSA_generate_parameters(Int32(bits), nil, 0, nil, nil, nil, nil)
		return des

	}
	
	public class func sign(data: Data) -> Data? {
		let dataPointer = data.makeUInt8DataPointer()
		let dataSize = data.count
		let size = UInt32(DSA_size(self.dsaKey!))
		let dsaSize = UnsafeMutablePointer<UInt32>.allocate(capacity: MemoryLayout<UInt32.Stride>.size)
		//dsaSize.pointee = size
		
		var result = Data.makeUInt8EmptyArray(ofSize: Int(size))
		
		let error = DSA_sign(0, dataPointer, Int32(dataSize), &result, dsaSize, dsaKey!)
		
		if error != 1 {
			//error occured
		}
		
		return Data(bytes: result, count: Int(dsaSize.pointee))
	}
	
	public class func verify(signature: Data, digest: Data) -> Bool {
		let sigPointer = signature.makeUInt8DataPointer()
		let sigSize = signature.count
		
		let digestPointer = digest.makeUInt8DataPointer()
		let digestSize = digest.count
	
		let error = DSA_verify(1, digestPointer, Int32(digestSize), sigPointer, Int32(sigSize), dsaKey!)
		
		if error == -1 {
			printCryptoError()
			return false
		}
		else if error == 0 {
			return false
		}
		
		return true
	}
	
	class func printCryptoError(){
		ERR_load_CRYPTO_strings()
		let err = UnsafeMutablePointer<CChar>.allocate(capacity: 130)
		ERR_error_string(ERR_get_error(), err)
		print("ENC ERROR \(String(cString: err))")
		print("Fuc error \(ERR_func_error_string(114))")
		print("Reason error \(ERR_reason_error_string(155))")
		err.deinitialize()
		err.deallocate(capacity: 130)
	}
}
