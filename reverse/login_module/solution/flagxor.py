def bitwise_xor(string, key):
    result = ""
    for char in string:
        ascii_val = ord(char)  # Get ASCII value of the character
        xor_val = ascii_val ^ key  # Perform XOR operation
        result += chr(xor_val)  # Convert XOR result back to character
    return result

input_string = "CCSC{1m_st1l1_tRy1n6_t0-l34rN_rust}"
xor_key = 13

xored_string = bitwise_xor(input_string, xor_key)
print(xored_string)