//
//  DemoClass.swift
//  CryptoLab
//
//  Created by Branko Popovic on 1/29/17.
//  Copyright © 2017 Branko Popovic. All rights reserved.
//

import Foundation
import OpenSSL

public class DemoClass: NSObject {
	public static let shared = DemoClass()
	
	public func printMD5Length() {
		print("MD5 Len Is: \(MD5_DIGEST_LENGTH) and it works")
	}
}
