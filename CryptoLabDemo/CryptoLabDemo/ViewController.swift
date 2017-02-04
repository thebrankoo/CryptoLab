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
