//
//  AESViewController.swift
//  CryptoLabDemo
//
//  Created by Branko Popovic on 4/11/17.
//  Copyright © 2017 Branko Popovic. All rights reserved.
//

import UIKit
import CryptoLab

class AESViewController: UIViewController, UIPickerViewDelegate, UIPickerViewDataSource {

	@IBOutlet weak var inputField: UITextView!
	@IBOutlet weak var outputField: UITextView!
	
	@IBOutlet weak var picker: UIPickerView!
	
	@IBOutlet weak var key: UITextField!
	@IBOutlet weak var iv: UITextField!
	
	fileprivate var selectedMode = ""
	fileprivate let modes = ["ecb", "cbc", "ofb", "cfb"]
	
    override func viewDidLoad() {
        super.viewDidLoad()
		self.iv.text = "some02ilaslkd0309".data(using: .utf8)!.hexEncodedString()
		selectedMode = modes.first!
		self.picker.delegate = self
		self.picker.dataSource = self
    }
	
	func numberOfComponents(in pickerView: UIPickerView) -> Int {
		return 1
	}
	
	func pickerView(_ pickerView: UIPickerView, numberOfRowsInComponent component: Int) -> Int {
		return modes.count
	}
	
	func pickerView(_ pickerView: UIPickerView, titleForRow row: Int, forComponent component: Int) -> String? {
		return modes[row]
	}
	
	func pickerView(_ pickerView: UIPickerView, didSelectRow row: Int, inComponent component: Int) {
		selectedMode = modes[row]
	}
	
	fileprivate func createAES() -> AESCipher? {
		var aes: AESCipher?
		do {
			if selectedMode == "ecb" {
				aes = try AESCipher(key: key.text!.data(using: .utf8)!, iv: iv.text!.data(using: .utf8)!, blockMode: .ecb)
			}
			else if selectedMode == "cbc" {
				aes = try AESCipher(key: key.text!.data(using: .utf8)!, iv: iv.text!.data(using: .utf8)!, blockMode: .cbc)
			}
			else if selectedMode == "ofb" {
				aes = try AESCipher(key: key.text!.data(using: .utf8)!, iv: iv.text!.data(using: .utf8)!, blockMode: .ofb)
			}
			else if selectedMode == "cfb" {
				aes = try AESCipher(key: key.text!.data(using: .utf8)!, iv: iv.text!.data(using: .utf8)!, blockMode: .cfb)
			}
			return aes
		}
		catch let err {
			print("\(err)")
			return nil
		}
	}
	
	@IBAction func encryptAction(_ sender: Any) {
		let toEncrypt = inputField.text!
		
		do {
			let aes = createAES()
			let encrypted = try aes?.encrypt(data: toEncrypt.data(using: .utf8)!)
			outputField.text = encrypted?.hexEncodedString()
		}
		catch let err {
			print("AES Error \(err)")
		}
	}
	
	@IBAction func decryptAction(_ sender: Any) {
		let toDecrypt = inputField.text!
		
		do {
			let aes = createAES()
			let decrypted = try aes?.decrypt(data: toDecrypt.data(using: .utf8)!)
			outputField.text = decrypted?.hexEncodedString()
		}
		catch let err {
			print("AES Error \(err)")
		}
	}
	
	
	
	
}
