//
//  main.cpp
//  Assignment 1
//
//  Created by Andy Truong on 25/9/20.
//  Copyright © 2020 Andy Truong. All rights reserved.
//

#include <iostream>
#include <math.h>
#include <stdio.h>
#include <vector>
using namespace std;

int readBinary(vector<int> v) {     //converts a binary value to integer
    int val = 0;
    for (int i = 0; i < v.size(); i++) {
        if (v[i] == 1) {
            val += v[i] * pow(2, v.size()-i-1);
        }
    }
    
    return val;
}

void printVector(vector<int> v) {   //print a given vector
    for (int i = 0; i < v.size(); i++)
        cout << v[i];
    cout << endl;
}

vector<int> toBinary(int n) {   //converts an integer to binary
    vector<int> returnVec;
    int i = 0;
    int num = n;
    int binaryNum[32];
    while (n > 0) {
        binaryNum[i] = n % 2;
        n = n / 2;
        i++;
    }
    
    for (int j = i - 1; j >= 0; j--)
        returnVec.push_back(binaryNum[j]);

    if (num == 1)
        returnVec.insert(returnVec.begin(), 0);
    
    return returnVec;
}

#include "SDES.h"

int main(int argc, const char * argv[]) {
    vector<int> tenBitKey;
    vector<int> p;
    string tenBitKeyString;
    string choice;
    string text;
    bool validKey = false;
    bool validChoice = false;
    bool validText = false;
    bool isEncrypt = true;
    
    while (!validKey) { //input for 10-bit key
        cout << "Enter 10 bit key: ";
        cin >> tenBitKeyString;
        
        if (tenBitKeyString.size() == 10) { //validation for size
            for (int i = 0; i < tenBitKeyString.size(); i++) {
                if (tenBitKeyString[i] == '0' || tenBitKeyString[i] == '1') //validation for 0's and 1's only
                    validKey = true;
                else
                    validKey = false;
            }
        }
    }
    
    for (int i = 0; i < tenBitKeyString.size(); i++)
        tenBitKey.push_back(tenBitKeyString[i] - 48);
    
    do {    //ask user if encrypting or decrypting
        cout << "Encrypt or Decrypt: (E/D) ";
        cin >> choice;
        
        if (choice == "E" || choice == "e" || choice == "D" || choice == "d")
            validChoice = true;
    } while (!validChoice);
    
    if (choice == "E" || choice == "e") {
        isEncrypt = true;
    } else if (choice == "D" || choice == "d")
        isEncrypt = false;
        
    do {    //plaintext/ciphertext input for program
        if (isEncrypt)
            cout << "Enter plaintext: ";
        else
            cout << "Enter ciphertext: ";
        cin >> text;
        if (text.size() == 8) {
            for (int i = 0; i < text.size(); i++) {
                if (text[i] == '0' || text[i] == '1')
                    validText = true;
                else {
                    validText = false;
                    break;
                }
            }
        }
    } while (!validText);
    
    for (int i = 0; i < text.size(); i++)
        p.push_back(text[i] - 48);
    
    SDES sdes(p, tenBitKey, isEncrypt); //encrypt/decrypt message
    
    
    return 0;
}

