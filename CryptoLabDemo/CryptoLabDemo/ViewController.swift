//
//  ViewController.swift
//  CryptoLabDemo
//
//  Created by Branko Popovic on 1/29/17.
//  Copyright © 2017 Branko Popovic. All rights reserved.
//

import UIKit
import CryptoLab

class ViewController: UIViewController {

	override func viewDidLoad() {
		super.viewDidLoad()
		
		//MARK: test code
		//DemoClass.shared.printMD5Length()
		
		
		//Hashing functions
		let hashFunction = MD5Hash()
		let data = "Test primer".data(using: .utf8)
		print("Hash code: \(hashFunction.hash(data: data!).hexEncodedString())")
		
	}

	override func didReceiveMemoryWarning() {
		super.didReceiveMemoryWarning()
		// Dispose of any resources that can be recreated.
	}
	


}


extension Data {
	func hexEncodedString() -> String {
		return map { String(format: "%02hhx", $0) }.joined()
	}
}
