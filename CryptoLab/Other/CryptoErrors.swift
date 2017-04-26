//
//  CryptoErrors.swift
//  CryptoLab
//
//  Created by Branko Popovic on 3/13/17.
//  Copyright © 2017 Branko Popovic. All rights reserved.
//

import Foundation
import OpenSSL

/**
Errors that can occure during cipher operations
*/
public enum CipherError: Error {
	/**
	Occurs when some part of cipher proces fails
	
	- parameters reason: Error description
	*/
	case cipherProcessFail(reason: String)
	
	/**
	Occurs when cipher key is invalid
	
	- parameters reason: Error description
	*/
	case invalidKey(reason: String)
}

struct CipherErrorReason {
	static var openSSLError: String {
		return "OpenSSL Error: " + cryptoOpenSSLError()
	}
	
	static let cipherEncryption = #function + " Encryption Error - " + openSSLError
	static let cipherDecryption = #function + " Decryption Error - " + openSSLError
	
	static let cipherInit = #function + " Init Error - " + openSSLError
	static let cipherUpdate = #function + " Update Error - " + openSSLError
	static let cipherFinish = #function + " Finish Error - " + openSSLError
	
	static func cryptoOpenSSLError() -> String {
		ERR_load_CRYPTO_strings()
		let err = UnsafeMutablePointer<CChar>.allocate(capacity: 130)
		ERR_error_string(ERR_get_error(), err)
		//print("ENC ERROR \(String(cString: err))")
	
		err.deinitialize()
		err.deallocate(capacity: 130)
		return String(cString: err)
	}
}
