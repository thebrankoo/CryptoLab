//
//  HashFunctionsViewController.swift
//  CryptoLabDemo
//
//  Created by Branko Popovic on 4/11/17.
//  Copyright © 2017 Branko Popovic. All rights reserved.
//

import UIKit
import CryptoLab

class HashFunctionsViewController: UIViewController, UIPickerViewDelegate, UIPickerViewDataSource {

	@IBOutlet weak var picker: UIPickerView!
	@IBOutlet weak var resultArea: UITextView!
	@IBOutlet weak var inputFIeld: UITextField!
	
	fileprivate let dataSource = ["md5", "sha1", "sha224", "sha256", "sha384", "sha512"]
	fileprivate var selectedType = ""
	
    override func viewDidLoad() {
        super.viewDidLoad()
		picker.delegate = self
		picker.dataSource = self
		selectedType = dataSource.first!
		
        // Do any additional setup after loading the view.
    }

	func numberOfComponents(in pickerView: UIPickerView) -> Int {
		return 1
	}
	
	func pickerView(_ pickerView: UIPickerView, numberOfRowsInComponent component: Int) -> Int {
		return dataSource.count
	}
	
	func pickerView(_ pickerView: UIPickerView, titleForRow row: Int, forComponent component: Int) -> String? {
		return dataSource[row]
	}
	
	func pickerView(_ pickerView: UIPickerView, didSelectRow row: Int, inComponent component: Int) {
		selectedType = dataSource[row]
	}

	fileprivate func hash() -> Data? {
		if let stringToHash = inputFIeld.text {
			if selectedType == "md5" {
				return stringToHash.md5()
			}
			else if selectedType == "sha1" {
				return stringToHash.sha1()
			}
			else if selectedType == "sha224" {
				return stringToHash.sha224()
			}
			else if selectedType == "sha256" {
				return stringToHash.sha256()
			}
			else if selectedType == "sha384" {
				return stringToHash.sha384()
			}
			else if selectedType == "sha512" {
				return stringToHash.sha512()
			}
		}
		return nil
	}
	
	@IBAction func hashAction(_ sender: Any) {
		resultArea.text = hash()?.hexEncodedString()
	}
}
