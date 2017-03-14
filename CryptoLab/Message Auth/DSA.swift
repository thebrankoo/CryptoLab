//
//  DSA.swift
//  CryptoLab
//
//  Created by Branko Popovic on 3/7/17.
//  Copyright © 2017 Branko Popovic. All rights reserved.
//

import Foundation
import OpenSSL

public class DSAAuth: NSObject {
	
	fileprivate let dsaCore: DSACore
	
	public var privateKey: String? {
		return dsaCore.extractPrivateKey()
	}
	
	public var publicKey: String? {
		return dsaCore.extractPublicKey()
	}
	
	public override init() {
		dsaCore = DSACore()
		super.init()
	}
	
	public init(publicKey: Data, privateKey: Data) {
		dsaCore = DSACore(publicKey: publicKey, privateKey: privateKey)
		super.init()
	}
	
	public func sign(data: Data) -> Data? {
		let signature = dsaCore.sign(data: data)
		return signature
	}
	
	public func verify(signature: Data, digest: Data) -> Bool {
		let verifyResult = dsaCore.verify(signature: signature, digest: digest)
		return verifyResult
	}
}

class DSACore: NSObject {
	
	fileprivate let pubKey: Data?
	fileprivate let privKey: Data?
	fileprivate var dsaKey: UnsafeMutablePointer<DSA>?
	
	init(publicKey: Data, privateKey: Data) {
		self.pubKey = publicKey
		self.privKey = privateKey
		super.init()
		dsaKey = generateDSA(fromPublicKey: publicKey, andPrivateKey: privateKey)
	}
	
	override init() {
		pubKey = Data()
		privKey = Data()
		super.init()
		generateDSA()
	}
	
	//MARK: DSA Key generator
	
	fileprivate func generateDSA(fromPublicKey pubK: Data, andPrivateKey privK: Data) -> UnsafeMutablePointer<DSA>? {
		if let dsa = generateDSA(fromPublicKey: pubK){
			let dsaPointer = UnsafeMutablePointer<UnsafeMutablePointer<DSA>?>.allocate(capacity: Int(DSA_size(dsa)))
			dsaPointer.initialize(to: dsa)
			
			let bioStruct : UnsafeMutablePointer<BIO> = BIO_new(BIO_s_mem())
			BIO_write(bioStruct, ((privK as NSData?)?.bytes)!, Int32(privK.count))
			let dsaNew = PEM_read_bio_DSAPrivateKey(bioStruct, dsaPointer, nil, nil)
			BIO_free(bioStruct)
			return dsaNew
		}
		return nil
	}
	
	fileprivate func generateDSA(fromPublicKey pubK: Data) -> UnsafeMutablePointer<DSA>? {
		
		let bioStruct : UnsafeMutablePointer<BIO> = BIO_new(BIO_s_mem())
		BIO_write(bioStruct, ((pubK as NSData?)?.bytes)!, Int32(pubK.count))
		
		let dsaNew = PEM_read_bio_DSA_PUBKEY(bioStruct, nil, nil, nil)
		BIO_free(bioStruct)
		return dsaNew
	}
	
	fileprivate func generateDSA() {
		dsaKey = generateDSAPrivPubKeys(key: generateDSAKeyWithParameters())
	}
	
	fileprivate func generateDSAPrivPubKeys(key: UnsafeMutablePointer<DSA>?) -> UnsafeMutablePointer<DSA>? {
		
		let dsaError = DSA_generate_key(key)
		
		if dsaError != 1 {
			print("DSA key generate error")
		}
		
		return key
	}
	
	fileprivate func generateDSAKeyWithParameters() -> UnsafeMutablePointer<DSA>? {
		let bits = 1024
		let des = DSA_generate_parameters(Int32(bits), nil, Int32(0), nil, nil, nil, nil)
		return des

	}
	
	//MARK: Key extractor
	
	fileprivate func extractPublicKey() -> String? {
		
		if let dsaKey = dsaKey {
			let bioStruct : UnsafeMutablePointer<BIO> = BIO_new(BIO_s_mem())
			let error = PEM_write_bio_DSA_PUBKEY(bioStruct, dsaKey)
			
			if error != 1 {
				print("PEM Write error")
				return nil
			}
			
			let size: size_t = BIO_ctrl_pending(bioStruct)
			let key = UnsafeMutablePointer<CChar>.allocate(capacity: size)
			
			let priLen = BIO_read(bioStruct, key, Int32(size+1))
			BIO_free(bioStruct)
			if priLen != Int32(size) {
				return nil
			}
			
			let convertResult = String.init(cString: key)
			var trimmedString = convertResult
			
			while true {
				if trimmedString.characters.last == "\n" || trimmedString.characters.last == "-" {
					break
				}
				else {
					trimmedString.remove(at: trimmedString.characters.index(before: trimmedString.endIndex))
				}
			}
			
			return trimmedString
		}
		return nil
	}
	
	fileprivate func extractPrivateKey() -> String? {
		if let dsaKey = dsaKey {
			let bioStruct : UnsafeMutablePointer<BIO> = BIO_new(BIO_s_mem())
			let error = PEM_write_bio_DSAPrivateKey(bioStruct, dsaKey, nil, nil, 0, nil, nil)
			
			if error != 1 {
				//error handle
				return nil
			}
			
			let size : size_t = BIO_ctrl_pending(bioStruct)
			let key = UnsafeMutablePointer<CChar>.allocate(capacity: size)
			let priLen = BIO_read(bioStruct, key, Int32(size+1))
			
			BIO_free(bioStruct)
			
			if priLen != Int32(size) {
				//logger.debug("PPKey len diff error")
				return nil
			}
			
			let convertResult  = String.init(cString: key)
			
			return convertResult
		}
		return nil
	}
	
	
	//MARK: Sign/Verifiy
	
	fileprivate func sign(data: Data) -> Data? {
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
	
	fileprivate func verify(signature: Data, digest: Data) -> Bool {
		let sigPointer = signature.makeUInt8DataPointer()
		let sigSize = signature.count
		
		let digestPointer = digest.makeUInt8DataPointer()
		let digestSize = digest.count
	
		let error = DSA_verify(1, digestPointer, Int32(digestSize), sigPointer, Int32(sigSize), dsaKey!)
		
		if error == -1 {
			//printCryptoError()
			return false
		}
		else if error == 0 {
			return false
		}
		
		return true
	}
	
//	class func printCryptoError(){
//		ERR_load_CRYPTO_strings()
//		let err = UnsafeMutablePointer<CChar>.allocate(capacity: 130)
//		ERR_error_string(ERR_get_error(), err)
//		print("ENC ERROR \(String(cString: err))")
//		print("Fuc error \(ERR_func_error_string(114))")
//		print("Reason error \(ERR_reason_error_string(155))")
//		err.deinitialize()
//		err.deallocate(capacity: 130)
//	}
}
