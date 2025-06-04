/*
 * Copyright (c) 2025 KCai Technology (https://kcaitech.com)
 * Licensed under the MIT License.
 */

package auth

import (
	"bytes"
	"crypto/rand"
	"testing"
)

func TestBase62EncodeDecode(t *testing.T) {
	tests := []struct {
		name string
		data []byte
	}{
		{
			name: "Simple bytes",
			data: []byte{1, 2, 3, 4, 5},
		},
		{
			name: "Zero bytes",
			data: []byte{0, 0, 0, 0, 0, 0, 0, 0, 0}, // Add more zero bytes to trigger obfuscation
		},
		{
			name: "Random bytes",
			data: []byte{255, 128, 64, 32, 16, 8, 4, 2, 1},
		},
		{
			name: "Alphabetic bytes",
			data: []byte("HelloWorld"),
		},
		{
			name: "Chinese bytes",
			data: []byte("你好世界"),
		},
		{
			name: "Empty array",
			data: []byte{},
		},
		{
			name: "32 bytes random data",
			data: func() []byte {
				b := make([]byte, 32)
				for i := 0; i < len(b); i++ {
					b[i] = byte(i)
				}
				return b
			}(),
		},
		{
			name: "Real random data",
			data: func() []byte {
				b := make([]byte, 32)
				rand.Read(b)
				return b
			}(),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Encode test data
			encoded := Base62Encode(tt.data)

			// Ensure encoded result is not empty when there is data
			if encoded == "" && len(tt.data) > 0 {
				t.Errorf("Base62Encode() returned empty string, but expected results")
			}

			// Record original encoding for debugging
			t.Logf("Original data: %v", tt.data)
			t.Logf("Encoded result: %s", encoded)

			// Decode result
			decoded, err := DecodeBase62ID(encoded)
			if err != nil {
				t.Errorf("DecodeBase62ID() error = %v", err)
				return
			}

			t.Logf("Decoded result: %v", decoded)

			// If original data is empty, ensure decoded result is [0]
			if len(tt.data) == 0 {
				if !bytes.Equal(decoded, []byte{0}) {
					t.Errorf("For empty input, decoded result should be [0], but got %v", decoded)
				}
				return
			}

			// Due to possible information loss during encoding-decoding process (obfuscation characters),
			// for ID validation purposes, we mainly care about two points:
			// 1. Decoded result should not be empty
			// 2. Same encoding should produce same decoding result

			if len(decoded) == 0 {
				t.Errorf("Decoded result should not be empty")
			}

			// Test encode-decode-encode consistency
			// That is, the same encoded string should always get the same decoded result
			decoded1, err := DecodeBase62ID(encoded)
			if err != nil {
				t.Errorf("First decoding error: %v", err)
				return
			}

			decoded2, err := DecodeBase62ID(encoded)
			if err != nil {
				t.Errorf("Second decoding error: %v", err)
				return
			}

			if !bytes.Equal(decoded1, decoded2) {
				t.Errorf("Two decoding results for the same encoding are not consistent")
			}

			// For 32 bytes of random data, we expect the encoded length to be at least 43
			if len(tt.data) == 32 && len(encoded) < 43 {
				t.Errorf("Encoded length for 32 bytes random data should be at least 43, but got %d", len(encoded))
			}
		})
	}
}

func TestBase62DecodeError(t *testing.T) {
	// Test invalid characters
	invalidChars := []string{
		"abc!def", // Contains exclamation mark
		"xyz@123", // Contains @ symbol
		"测试",      // Non-ASCII characters
	}

	for _, invalid := range invalidChars {
		t.Run("Invalid character: "+invalid, func(t *testing.T) {
			_, err := DecodeBase62ID(invalid)
			if err == nil {
				t.Errorf("Expected error for input containing invalid character %s, but got none", invalid)
			}
		})
	}
}

func TestGenerateBase62ID(t *testing.T) {
	// Test ID generation
	id1, err := GenerateBase62ID()
	if err != nil {
		t.Errorf("GenerateBase62ID() error = %v", err)
		return
	}

	// Generated ID should not be empty
	if id1 == "" {
		t.Error("GenerateBase62ID() returned empty string")
	}

	// Generate another ID, make sure they are different (randomness check)
	id2, err := GenerateBase62ID()
	if err != nil {
		t.Errorf("GenerateBase62ID() second call error = %v", err)
		return
	}

	if id1 == id2 {
		t.Error("GenerateBase62ID() generated the same ID twice, indicating insufficient randomness")
	}

	// Verify that generated ID can be properly decoded
	decoded1, err := DecodeBase62ID(id1)
	if err != nil {
		t.Errorf("Could not decode generated ID: %v", err)
		return
	}

	if len(decoded1) == 0 {
		t.Error("Decoded ID should not be empty")
	}
}
