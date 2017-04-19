//
//  RSAViewController.swift
//  CryptoLabDemo
//
//  Created by Branko Popovic on 4/19/17.
//  Copyright © 2017 Branko Popovic. All rights reserved.
//

import UIKit
import CryptoLab

class RSAViewController: UIViewController {

	@IBOutlet weak var inputField: UITextView!
	@IBOutlet weak var outputField: UITextView!
	
	fileprivate var rsaCrypter: RSACipher?
	
    override func viewDidLoad() {
        super.viewDidLoad()
		rsaCrypter = RSACipher(padding: .pkcs1)
		
    }

	@IBAction func encryptAction(_ sender: Any) {
		let toEncrypt = inputField.text
		
		do {
			let encrypted = try rsaCrypter?.encrypt(data: toEncrypt!.data(using: .utf8)!)
			outputField.text = encrypted?.base64EncodedString()
		}
		catch let err {
			print("RSA Error \(err)")
		}
	}
	
	
	@IBAction func decryptAction(_ sender: Any) {
		let toDecrypt = inputField.text!
		
		do {
			let decrypted = try rsaCrypter?.decrypt(data: Data(base64Encoded: toDecrypt)!)  //toDecrypt!.data(using: .utf8)!)
			outputField.text = String(data: decrypted!, encoding: .utf8)
		}
		catch let err {
			print("RSA Error \(err)")
		}
	}

	@IBAction func privateKeyAction(_ sender: Any) {
		outputField.text = rsaCrypter?.privateKey
	}
	
	@IBAction func publicKeyAction(_ sender: Any) {
		outputField.text = rsaCrypter?.publicKey
	}
	
}
