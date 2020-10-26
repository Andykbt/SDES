//
//  SDES.h
//  Assignment 1
//
//  Created by Andy Truong on 26/9/20.
//  Copyright © 2020 Andy Truong. All rights reserved.
//

#ifndef SDES_h
#define SDES_h

class SDES {
private:
    //vectors to hold all permutations
    vector<int> IP = {2, 6, 3, 1, 4, 8, 5, 7};
    vector<int> IPInverse = {4, 1, 3, 5, 7, 2, 8, 6};
    vector<int> P10 = {3, 5, 2, 7, 4, 10, 1, 9, 8, 6};
    vector<int> P8 = {6, 3, 7, 4, 8, 5, 10, 9};
    vector<int> EP = {4, 1, 2, 3, 2, 3, 4, 1};
    vector<int> P4 = {2, 4, 3, 1};
    int SBOX0[4][4] = { {1, 0, 3, 2},
                        {3, 2, 1, 0},
                        {0, 2, 1, 3},
                        {3, 1, 3, 2}};
    int SBOX1[4][4] = { {0, 1, 2, 3},
                        {2, 0, 1, 3},
                        {3, 0, 1, 0},
                        {2, 1, 0, 3}};

    bool isEncrypt;
    
    //values that need to be saved for output
    vector<int> plainText;
    vector<int> cipherText;
    vector<int> tenBitKey;
    vector<int> k1;
    vector<int> k2;
    
public:
    SDES(vector<int> text, vector<int> tenBitKey, bool isEncrypt) {
        if (isEncrypt)
            this->plainText = text;
        else
            this->cipherText = text;
        
        this->tenBitKey = tenBitKey;
        
        generateKeys();
        if (isEncrypt)
            encryptPlainText();
        else
            decryptCipherText();
            
        printResults();
    }
    
    void printResults() {
        cout << "####################" << endl;
        cout << "10 bit key: ";
            printVector(tenBitKey);
        cout << "plain Text: ";
            printVector(plainText);
        cout << "key 1: ";
            printVector(k1);
        cout << "key 2: ";
            printVector(k2);
        cout << "cipher Text: ";
            printVector(cipherText);
        cout << "####################" << endl;
    }
    
    void printKeys() {
        for (int i = 0; i < k1.size(); i++)
            cout << k1[i];
        
        for (int i = 0; i < k2.size(); i++)
            cout << k2[i];
    }
    
    void generateKeys() {
        //P10
        vector<int> P10permutation = P10permute(tenBitKey);
        
        //split bits
        vector<int> f5; //first 5 bits
        vector<int> l5; //last 5 bits
        
        for (int i = 0; i < P10.size(); i++) {
            if (i < 5)
                f5.push_back(P10permutation[i]);
            else
                l5.push_back(P10permutation[i]);
        }
        
        //LS-1
        f5 = leftShift1(f5);
        l5 = leftShift1(l5);
        
        //Key 1
        k1 = P8permute(f5, l5);
        
        //LS-2
        f5 = leftShift2(f5);
        l5 = leftShift2(l5);
        
        //Key 2
        k2 = P8permute(f5, l5);
        
        //printKeys();
    }
    
    void encryptPlainText() {
        vector<int> IPpermutation = IPpermute(plainText);   //IP permutation
        vector<int> f4;
        vector<int> l4;
        
        for (int i = 0; i < IPpermutation.size(); i++) {    //getting first 4 bits and last 4 bits
            if (i < 4)
                f4.push_back(IPpermutation[i]);
            else
                l4.push_back(IPpermutation[i]);
        }
        
        vector<int> OR = exclusiveOR(EPpermute(l4), k1);    //exclusiveOR
        vector<int> S0;
        vector<int> S1;
        for (int i = 0; i < OR.size(); i++) {
            if (i < 4)
                S0.push_back(OR[i]);
            else
                S1.push_back(OR[i]);
        }
        
        vector<int> S0AndS1;
        vector<int> sbox0val = SBOX(S0, SBOX0);
        vector<int> sbox1val = SBOX(S1, SBOX1);
        
        for (int i = 0; i < sbox0val.size(); i++)
            S0AndS1.push_back(sbox0val[i]);
        for (int i = 0; i < sbox1val.size(); i++)
            S0AndS1.push_back(sbox1val[i]);
        
        /*   SWITCH   */
        vector<int> tmp = l4;
        l4 = exclusiveOR(P4permute(S0AndS1), f4);
        f4 = tmp;
        OR = exclusiveOR(EPpermute(l4), k2);
        
        
        S0.clear();
        S1.clear();
        for (int i = 0; i < OR.size(); i++) {
            if (i < 4)
                S0.push_back(OR[i]);
            else
                S1.push_back(OR[i]);
        }
        
        S0AndS1.clear();
        sbox0val = SBOX(S0, SBOX0);
        sbox1val = SBOX(S1, SBOX1);
        for (int i = 0; i < sbox0val.size(); i++)
            S0AndS1.push_back(SBOX(S0, SBOX0)[i]);
        for (int i = 0; i < SBOX(S1, SBOX1).size(); i++)
            S0AndS1.push_back(SBOX(S1, SBOX1)[i]);
        
        vector<int> tmp1 = exclusiveOR(P4permute(S0AndS1), f4);
        for (int i = 0; i < l4.size(); i++)
            tmp1.push_back(l4[i]);
        
        cipherText = IPInversePermute(tmp1);
    }
    
    void decryptCipherText() {
        vector<int> IPpermutation = IPpermute(cipherText);
        vector<int> f4;
        vector<int> l4;
        
        for (int i = 0; i < IPpermutation.size(); i++) {
            if (i < 4)
                f4.push_back(IPpermutation[i]);
            else
                l4.push_back(IPpermutation[i]);
        }
        
        vector<int> OR = exclusiveOR(EPpermute(l4), k2);
        vector<int> S0;
        vector<int> S1;
        for (int i = 0; i < OR.size(); i++) {
            if (i < 4)
                S0.push_back(OR[i]);
            else
                S1.push_back(OR[i]);
        }
        
        vector<int> S0AndS1;
        vector<int> sbox0val = SBOX(S0, SBOX0);
        vector<int> sbox1val = SBOX(S1, SBOX1);
        
        for (int i = 0; i < sbox0val.size(); i++)
            S0AndS1.push_back(sbox0val[i]);
        for (int i = 0; i < sbox1val.size(); i++)
            S0AndS1.push_back(sbox1val[i]);
        
        /*   SWITCH   */
        vector<int> tmp = l4;
        l4 = exclusiveOR(P4permute(S0AndS1), f4);
        f4 = tmp;
        OR = exclusiveOR(EPpermute(l4), k1);//corrent
        
        
        S0.clear();
        S1.clear();
        for (int i = 0; i < OR.size(); i++) {
            if (i < 4)
                S0.push_back(OR[i]);
            else
                S1.push_back(OR[i]);
        }
        
        S0AndS1.clear();
        sbox0val = SBOX(S0, SBOX0);
        sbox1val = SBOX(S1, SBOX1);
        for (int i = 0; i < sbox0val.size(); i++)
            S0AndS1.push_back(SBOX(S0, SBOX0)[i]);
        for (int i = 0; i < SBOX(S1, SBOX1).size(); i++)
            S0AndS1.push_back(SBOX(S1, SBOX1)[i]);
        
        vector<int> tmp1 = exclusiveOR(P4permute(S0AndS1), f4);
        for (int i = 0; i < l4.size(); i++)
            tmp1.push_back(l4[i]);
        
        plainText = IPInversePermute(tmp1);
    }
    
    vector<int> IPpermute(vector<int> v) {
        vector<int> returnVec;
        
        for (int i = 0; i < IP.size(); i++)
            returnVec.push_back(v[IP[i]-1]);
        
        return returnVec;
    }
    
    vector<int> IPInversePermute(vector<int> v) {
        vector<int> returnVec;
        
        for (int i = 0; i < IPInverse.size(); i++)
            returnVec.push_back(v[IPInverse[i]-1]);
        
        return returnVec;
    }
    
    vector<int> P10permute(vector<int> v) {
        vector<int> returnVec;
        
        for (int i = 0; i < P10.size(); i++)
            returnVec.push_back(v[P10[i]-1]);
        
        return returnVec;
    }
    
    vector<int> P8permute(vector<int> left, vector<int> right) {
        vector<int> returnVec;
        vector<int> leftAndRight;
        
        for (int i = 0; i < left.size(); i++)
            leftAndRight.push_back(left[i]);
        for (int i = 0; i < right.size(); i++)
            leftAndRight.push_back(right[i]);
            
        
        for (int i = 0; i < P8.size(); i++)
            returnVec.push_back(leftAndRight[P8[i]-1]);
        
        return returnVec;
    }
    
    vector<int> P4permute(vector<int> v) {
        vector<int> returnVec;
        
        for (int i = 0; i < P4.size(); i++)
            returnVec.push_back(v[P4[i]-1]);
        
        return returnVec;
    }
    
    vector<int> EPpermute(vector<int> v) {
        vector<int> returnVec;
        
        for (int i = 0; i < EP.size(); i++)
            returnVec.push_back(v[EP[i]-1]);
        
        return returnVec;
    }
    
    vector<int> leftShift1(vector<int> v) {
        vector<int> returnVec;
        
        for (int i = 0; i < v.size(); i++) {
            if (i == v.size()-1)
                returnVec.push_back(v[0]);
            else
                returnVec.push_back(v[i+1]);
        }
        
        return returnVec;
    }
    
    vector<int> leftShift2(vector<int> v) {
        vector<int> returnVec;
        
        for (int i = 0; i < v.size(); i++) {
            if (i >= v.size() - 2)
                returnVec.push_back(v[i-3]);
            else
                returnVec.push_back(v[i+2]);
        }
        return returnVec;
    }
    
    vector<int> exclusiveOR(vector<int> v, vector<int> key) {
        vector<int> returnVec;
        for (int i = 0; i < v.size(); i++) {
            if (v[i] != key[i]) {
                returnVec.push_back(1);
            } else {
                returnVec.push_back(0);
            }
        }
        /*cout << endl << "exclusive or: " << endl;
        printVector(v);
        printVector(key);
        printVector(returnVec);*/
        
        return returnVec;
    }
    
    vector<int> SBOX(vector<int> v, int arr[4][4]) {
        vector<int> returnVec;
        vector<int> row = {v[0], v[3]};
        vector<int> col = {v[1], v[2]};
        vector<int> tmp = toBinary(arr[readBinary(row)][readBinary(col)]);
        returnVec = tmp;
        
        //cout << "[" << readBinary(row) << "][" << readBinary(col) << "] = ";
        //cout << arr[readBinary(row)][readBinary(col)] << " = ";
        //printVector(returnVec);
        
        if (tmp.size() == 0)
            returnVec = {0, 0};
        return returnVec;
    }
    
    
};

#endif /* SDES_h */
