/*
 * Copyright (c) 2025 KCai Technology (https://kcaitech.com)
 * Licensed under the MIT License.
 */

package main

import (
	"crypto/rand"
	"fmt"
	"math/big"
)

// Base62 character set (0-9, a-z, A-Z)
const base62Chars = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"

// base62Encode Encodes a byte slice to base62 string
func Base62Encode(data []byte) string {
	// Calculate required capacity: one byte needs at most 2 base62 characters
	capacity := len(data) * 2
	result := make([]byte, 0, capacity)

	// Convert byte slice to a big integer
	var n big.Int
	n.SetBytes(data)

	// Base62 base
	base := big.NewInt(62)
	zero := big.NewInt(0)
	mod := new(big.Int)

	// Perform base62 conversion
	for n.Cmp(zero) > 0 {
		n.DivMod(&n, base, mod)
		result = append(result, base62Chars[mod.Int64()])
	}

	// Add obfuscated encoding for remaining bytes to ensure fixed length
	// Even if the input's low bytes are all zeros, still maintain a certain length
	for i := 0; i < len(data)/8 && len(result) < 43; i++ {
		result = append(result, base62Chars[data[i]%62])
	}

	// Reverse the result (because we added from low to high)
	for i, j := 0, len(result)-1; i < j; i, j = i+1, j-1 {
		result[i], result[j] = result[j], result[i]
	}

	return string(result)
}

// Base62Decode Decodes a base62 string to byte slice
// Note: Since Base62Encode uses an obfuscation algorithm, this decoding function may not fully restore original data
// But for use as an ID, this decoding is sufficient
func DecodeBase62ID(id string) ([]byte, error) {
	// If input is empty, return default value
	if id == "" {
		return []byte{0}, nil
	}

	// Create mapping from base62 character to value
	charToVal := make(map[byte]int, 62)
	for i := 0; i < len(base62Chars); i++ {
		charToVal[base62Chars[i]] = i
	}

	// Create big integer for calculation
	res := new(big.Int).SetInt64(0)
	base := new(big.Int).SetInt64(62)

	// Since Base62Encode function adds obfuscation characters during encoding, precise decoding is difficult
	// Here we mainly decode the numerical part

	// Iterate through ID string, from high to low
	for i := 0; i < len(id); i++ {
		// Get current character's value
		val, ok := charToVal[id[i]]
		if !ok {
			return nil, fmt.Errorf("invalid Base62 character: %c", id[i])
		}

		// Multiply by base and add current value
		res.Mul(res, base)
		res.Add(res, big.NewInt(int64(val)))
	}

	// Convert big integer back to byte slice
	bytes := res.Bytes()

	// If result is empty (possibly because input is "0"), return a zero byte
	if len(bytes) == 0 {
		return []byte{0}, nil
	}

	return bytes, nil
}

func GenerateUserID() (string, error) {
	return GenerateBase62String(10)
}

func GenerateBase62ID() (string, error) {
	b := make([]byte, 16) // 16 bytes, the length of a uuid, generates about 22 characters
	_, err := rand.Read(b)
	if err != nil {
		return "", fmt.Errorf("failed to generate random bytes: %w", err)
	}
	// Use base62 encoding (digits + uppercase and lowercase letters) to shorten ID length
	return Base62Encode(b), nil
}

func GenerateByteID() ([]byte, error) {
	b := make([]byte, 16)
	_, err := rand.Read(b)
	if err != nil {
		return nil, fmt.Errorf("failed to generate random bytes: %w", err)
	}
	return b, nil
}

// func GenerateBase62IDWithLen(length int) (string, error) {
// 	b := make([]byte, length) // 16 bytes, the length of a uuid
// 	_, err := rand.Read(b)
// 	if err != nil {
// 		return "", fmt.Errorf("failed to generate random bytes: %w", err)
// 	}
// 	// Use base62 encoding (digits + uppercase and lowercase letters) to shorten ID length
// 	return Base62Encode(b), nil
// }

// generateBase62String Generates a random base62 string of specified length
func GenerateBase62String(length int) (string, error) {
	result := make([]byte, length)
	// Base62 base
	base := big.NewInt(62)
	for i := 0; i < length; i++ {
		// Generate random number 0-61
		n, err := rand.Int(rand.Reader, base)
		if err != nil {
			// If an error occurs, use a simple fallback method
			result[i] = base62Chars[i%62]
			continue
		}
		result[i] = base62Chars[n.Int64()]
	}
	return string(result), nil
}
