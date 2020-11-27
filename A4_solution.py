"""
-----------------------------
CP460 (Fall 2020)
Name: Shyam Dave
ID:180332030
Assignment 4
-----------------------------
"""
import math
import string
import mod
import matrix
import utilities

#---------------------------------
# Q1: Modular Arithmetic Library #
#---------------------------------

# solution is available in mod.py


#---------------------------------
#     Q2: Decimation Cipher      #
#---------------------------------
#-----------------------------------------------------------
# Parameters:   plaintext (str)
#               key (tuple): (base(str), k(int))
# Return:       ciphertext (str)
# Description:  Encryption using Decimation Cipher
#               Encrypts only characters defined in the base
#               Case of characters should be preserved (whenever possible)
# Asserts:      plaintext is a string
# Errors:       if invalid key, e.g. has no multiplicative inverse -->
#                   print error msg and return empty string
#-----------------------------------------------------------
def e_decimation(plaintext, key):
    assert type(plaintext) == str
    ciphertext = ''
    base, num = key[0], key[1]
    if mod.has_mul_inv(num, len(base)) == False:
        print("Error(e_decimation): Invalid key")
        return ""
    else:
        for x in plaintext:
            if x.lower() in base:
                position = base.find(x.lower())
                if x.isupper():
                    ciphertext += base[mod.mul(position, num, len(base))].upper()
                else:
                    ciphertext += base[mod.mul(position, num, len(base))].lower()
            else:
                ciphertext += x
    return ciphertext


#-----------------------------------------------------------
# Parameters:   ciphertext (str)
#               key (tuple): (base(str), k(int))
# Return:       plaintext (str)
# Description:  Decryption using Decimation Cipher
#               Decrypts only characters defined in the base
#               Case of characters should be preserved (whenever possible)
# Asserts:      ciphertext is a string
# Errors:       if invalid key, e.g. has no multiplicative inverse -->
#                   print error msg and return empty string
#-----------------------------------------------------------
def d_decimation(ciphertext, key):
    assert type(ciphertext) == str
    plaintext = ''
    base, num = key[0], key[1]
    if mod.has_mul_inv(num, len(base)) == False:
        print("Error(d_decimation): Invalid key")
        return ""
    else:
        return_key = mod.mul_inv(num, len(base))
        for x in ciphertext:
            if x.lower() in base:
                position = base.find(x.lower())
                if x.isupper():
                    plaintext += base[mod.mul(position, return_key, len(base))].upper()
                else:
                    plaintext += base[mod.mul(position, return_key, len(base))].lower()
            else:
                plaintext += x
    return plaintext


#-----------------------------------------------------------
# Parameters:   ciphertext (str)
# Return:       key (tuple) (base,k)
#               plaintext (str)
#               counter (int): number of attempted keys
# Description:  Cryptanalysis of Decimation Cipher
#               Assumes subset of get_base('lower) + get_base('nonalpha')
#                 starting at 'a' and holding consecutive characters
#               If it fails, return: '','',0
# Asserts:      ciphertext is a non-empty string
#-----------------------------------------------------------
def cryptanalysis_decimation(ciphertext):
    assert type(ciphertext) == str and len(ciphertext) > 0
    min_b = 'abc'
    search = False
    plaintext = ''
    counter, key_value, base_index = 0, 0, 0
    base = utilities.get_base('lower') + utilities.get_base('nonalpha')
    dict = utilities.load_dictionary(utilities.DICT_FILE)
    while min_b < base and search == False:
        table = mod.mul_inv_table(len(min_b))

        table_index = 0
        search = False

        while table_index < len(table[1]) and search is False:
            if table[0][table_index] != 1 and table[1][table_index] != 'NA':
                key_base = min_b
                key_k = table[0][table_index]
                plaintext = d_decimation(ciphertext, (key_base, key_k))
                counter += 1

                if utilities.is_plaintext(plaintext, dict, 0.9) == True:
                    search = True
                    key_value = key_k
            table_index += 1

        if search == False:
            min_b = base[:4 + base_index]
            base_index += 1

    if search == True:
        return (key_base, key_value), plaintext, counter
    return '', '', 0


#---------------------------------
#      Q3: Affine Cipher         #
#---------------------------------
#-----------------------------------------------------------
# Parameters:   plaintext (str)
#               key (tuple): (base(str), [alpha(int),beta(int)])
# Return:       ciphertext (str)
# Description:  Encryption using Affine Cipher
#               Encrypts only characters defined in the base
#               Case of characters should be preserved (whenever possible)
# Asserts:      plaintext is a string
# Errors:       if invalid key -->
#                   print error msg and return empty string
#-----------------------------------------------------------
def e_affine(plaintext, key):
    ciphertext, base = "", key[0]

    if (mod.has_mul_inv(key[1][0], len(base))) == False:
        print("Error(e_affine): Invalid key")
        return ""
    
    for x in plaintext:
        if x.lower() in base:
            position = base.find(x.lower())
            mult = mod.mul(key[1][0], position, len(base))
            row = mod.add(key[1][1], mult, len(base))
            if x.isupper():
                ciphertext += base[row].upper()
            else:
                ciphertext += base[row].lower()
            
        else:
            ciphertext += x
    
    return ciphertext


#-----------------------------------------------------------
# Parameters:   ciphertext (str)
#               key (str,[int,int])
# Return:       plaintext (str)
# Description:  Decryption using Affine Cipher
#               key is tuple (baseString,[alpha,beta])
#               Does not decrypt characters not in baseString
#               Case of letters should be preserved
# Errors:       if key can not be used for decryption
#                   print error msg and return empty string
#-----------------------------------------------------------
def d_affine(ciphertext, key):
    plaintext = ""
    base = key[0]
    m = len(base)
    
    if (mod.has_mul_inv(key[1][0], m)) == False:
        print("Error(d_affine): Invalid key")
        return ""
    
    for x in ciphertext:
        if x.lower() in base:
            position = base.find(x.lower())
            subtr = mod.sub(position, key[1][1], m)
            inverse = mod.mul_inv(key[1][0], m)
            row = mod.mul(inverse, subtr, m)
            
            if x.isupper():
                plaintext += base[row].upper()
            else:
                plaintext += base[row].lower()
        else:
            plaintext += x
            
    return plaintext


#-----------------------------------------------------------
# Parameters:   ciphertext (str)
# Return:       key (tuple) (base,k)
#               plaintext (str)
#               counter (int): number of attempted keys
# Description:  Cryptanalysis of Affine Cipher
#               Assumes subset of get_base('lower) + get_base('nonalpha')
#                 starting at 'a' and holding consecutive characters
#               If it fails, return: '','',0
# Asserts:      ciphertext is a non-empty string
#-----------------------------------------------------------
def cryptanalysis_affine(ciphertext):
    plaintext = ""
    counter = 0
    min_pos = 2
    base = utilities.get_base('lower') + utilities.get_base('nonalpha')
    dict = utilities.load_dictionary(utilities.DICT_FILE)
    while min_pos < len(base):
        alpha = 0
        while alpha < len(base[:min_pos]):
            beta = 0
            if(alpha == 1):beta = 1
            while beta < len(base[:min_pos]):
    
                key = (base[:min_pos], [alpha, beta])
                
                if mod.has_mul_inv(alpha, len(base[:min_pos])):
                    counter += 1
              
                    plaintext = d_affine(ciphertext, key)
                    if utilities.is_plaintext(plaintext, dict, 0.9) == True:
                       
                        return key, plaintext, counter  
                beta += 1
            alpha += 1
        min_pos += 1
    
    return "", "", 0

#---------------------------------
#      Q4: Matrix Library        #
#---------------------------------

# solution is available in matrix.py


#---------------------------------
#       Q5: Hill Cipher          #
#---------------------------------
#-----------------------------------------------------------
# Parameters:   plaintext (str)
#               key (str)
# Return:       ciphertext (str)
# Description:  Encryption using Hill Cipher, 2x2 (mod 26)
#               key is a string consisting of 4 characters
#                   if key is too short, make it a running key
#                   if key is too long, use first 4 characters
#               Encrypts only alphabet characters
#               Deals with plaintext as lower case, 
#               and produces upper case ciphertext
#               If necessary use default padding
# Errors:       if key is is invalid:
#                   print error msg and return empty string
# Asserts:      plaintext is a non-empty string
#-----------------------------------------------------------
def e_hill(plaintext, key):
    assert type(plaintext) == str  and len(plaintext) > 0
    
    if isinstance(key, str) == False:
        print("Error(e_hill): Invalid key")
        return ""
    ciphertext, base = "", utilities.get_base("upper")

    temp_k = key
    if len(temp_k) < 4:
        i = 0
        while len(temp_k) < 4:
            if i >= len(key):
                i = 0
            temp_k += key[i]
    elif len(temp_k) > 4:
        temp_k = key[:4]
        
    key_m = matrix.new_matrix(2, 2, 0)
    x = 0
    for r in range(2):
        for c in range(2):
            key_m[r][c] = base.find(temp_k[x].upper())
            x += 1
            
    if isinstance(matrix.inverse(key_m, 26), str):
        print("Error(e_hill): key is not invertible")
        return ""
    
    temp_text = plaintext
    temp_base = utilities.get_base("nonalpha") + "\n\t "
    positions = utilities.get_positions(temp_text, temp_base)
    temp_text = utilities.clean_text(temp_text, temp_base)
    
    if len(temp_text) % 2 != 0:
        temp_text += utilities.PAD
   
    table = matrix.new_matrix(2, 1, 0)
    x = 0
    while x < len(temp_text):
        table[0][0] = base.find(temp_text[x].upper())
        table[1][0] = base.find(temp_text[x + 1].upper())
        
        table = matrix.mul(key_m, table)
        table = matrix.matrix_mod(table, 26)

        ciphertext += base[table[0][0]]
        ciphertext += base[table[1][0]]
        
        x += 2
        
    if len(positions) > 0:
            ciphertext = utilities.insert_positions(ciphertext, positions)
    
    return ciphertext


#-----------------------------------------------------------
# Parameters:   ciphertext (str)
#               key (str)
# Return:       plaintext (str)
# Description:  Decryption using Hill Cipher, 2x2 (mod 26)
#               key is a string consisting of 4 characters
#                   if key is too short, make it a running key
#                   if key is too long, use first 4 characters
#               Decrypts only alphabet characters
#               Deals with ciphertext as upper case, 
#               and produces lower case plaintext
#               If necessary remove paddingpadding
# Errors:       if key is is invalid:
#                   print error msg and return empty string
# Asserts:      ciphertext is a non-empty string
#-----------------------------------------------------------
def d_hill(ciphertext, key):
    
    plaintext = ""
    base = utilities.get_base("lower")
    
    if not(isinstance(key, str)):
        print("Error(d_hill): Invalid key")
        return ""
    
    temp_k = key
    if len(temp_k) < 4:
        i = 0
        while len(temp_k) < 4:
            if i >= len(key):
                i = 0
            temp_k += key[i]
    elif len(temp_k) > 4:
        temp_k = key[:4]
        
    key_m = matrix.new_matrix(2, 2, 0)
    x = 0
    
    for i in range(2):
        for j in range(2):
            key_m[i][j] = base.find(temp_k[x].lower())
            x += 1
            
    if isinstance(matrix.inverse(key_m, 26), str) == True:
        print("Error(d_hill): key is not invertible")
        return ""
    
    key_m = matrix.inverse(key_m, 26)
    
    temp_text = ciphertext
    temp_base = utilities.get_base("nonalpha") + "\n\t "
    positions = utilities.get_positions(temp_text, temp_base)
    temp_text = utilities.clean_text(temp_text, temp_base)
    
    x = 0
    table = matrix.new_matrix(2, 1, 0)
    while x < len(temp_text):
        table[0][0] = base.find(temp_text[x].lower())
        table[1][0] = base.find(temp_text[x + 1].lower())
        
        table = matrix.mul(key_m, table)
        table = matrix.matrix_mod(table, 26)

        plaintext += base[table[0][0]]
        plaintext += base[table[1][0]]
        
        x += 2
        
    if plaintext[len(plaintext) - 1] == "q":
        plaintext = plaintext[:-1]
        
    if len(positions) > 0:
            plaintext = utilities.insert_positions(plaintext, positions)
    
    return plaintext
