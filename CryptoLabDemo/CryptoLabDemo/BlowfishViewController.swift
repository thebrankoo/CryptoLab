//
//  BlowfishViewController.swift
//  CryptoLabDemo
//
//  Created by Branko Popovic on 4/18/17.
//  Copyright © 2017 Branko Popovic. All rights reserved.
//

import UIKit
import CryptoLab

public struct Encrypted {
	let encryptedData: Data
	var stringRepresentation: String? {
		return encryptedData.hexEncodedString()
	}
}

class BlowfishViewController: UIViewController {

	@IBOutlet weak var input: UITextView!
	@IBOutlet weak var output: UITextView!
	
	@IBOutlet weak var keyField: UITextField!
	@IBOutlet weak var ivField: UITextField!
	
	fileprivate let iv = "12345678"
	
    override func viewDidLoad() {
        super.viewDidLoad()
		ivField.text = iv
    }

	var currentData: Data?

	@IBAction func encryptAction(_ sender: Any) {
		if let key = keyField.text?.data(using: .utf8), let toEnc = input.text?.data(using: .utf8) {
			let iv = ivField.text!.data(using: .utf8)!
			let bfCrypto = BlowfishCipher(key: key, iv: iv, encryptionMode: .ofb64)
			
			do {
				let encryptedData = try bfCrypto.encrypt(data: toEnc)
				output.text = encryptedData.base64EncodedString()
			}
			catch let err {
				print("Blowfish error \(err)")
			}
		}
	}
	
	@IBAction func decryptAction(_ sender: Any) {
		if let key = keyField.text?.data(using: .utf8), let toDec = Data(base64Encoded: input.text!) {
			let iv = ivField.text!.data(using: .utf8)!
			let bfCrypto = BlowfishCipher(key: key, iv: iv, encryptionMode: .ofb64)
			
			do {
				let decrypted = try bfCrypto.decrypt(data: toDec)
				output.text = String(data: decrypted, encoding: .utf8)
			}
			catch let err {
				print("Blowfish error \(err)")
			}
		}
	}
	
}
