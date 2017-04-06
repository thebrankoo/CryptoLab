//
//  Random.swift
//  CryptoLab
//
//  Created by Branko Popovic on 4/6/17.
//  Copyright © 2017 Branko Popovic. All rights reserved.
//

import Foundation
import OpenSSL

public class RandomCore: NSObject {
	public static func generateRandomBytes(ofLength n: Int) -> Data? {
		var randData = Data.makeUInt8EmptyArray(ofSize: n)
		if RAND_bytes(&randData, Int32(n)) != 1 {
			return nil
		}
		
		return Data(bytes: randData)
	}
	
	public static func generatePseudoRandomBytes(ofLength n: Int) -> Data? {
		var randData = Data.makeUInt8EmptyArray(ofSize: n)
		
		if RAND_pseudo_bytes(&randData, Int32(n)) != 1 {
			return nil
		}
		
		return Data(bytes: randData)
	}
}
