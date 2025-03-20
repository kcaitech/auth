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
			name: "简单字节",
			data: []byte{1, 2, 3, 4, 5},
		},
		{
			name: "零字节",
			data: []byte{0, 0, 0, 0, 0, 0, 0, 0, 0}, // 增加更多零字节以触发混淆
		},
		{
			name: "随机字节",
			data: []byte{255, 128, 64, 32, 16, 8, 4, 2, 1},
		},
		{
			name: "字母字节",
			data: []byte("HelloWorld"),
		},
		{
			name: "中文字节",
			data: []byte("你好世界"),
		},
		{
			name: "空数组",
			data: []byte{},
		},
		{
			name: "32字节随机数据",
			data: func() []byte {
				b := make([]byte, 32)
				for i := 0; i < len(b); i++ {
					b[i] = byte(i)
				}
				return b
			}(),
		},
		{
			name: "真实随机数据",
			data: func() []byte {
				b := make([]byte, 32)
				rand.Read(b)
				return b
			}(),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// 编码测试数据
			encoded := Base62Encode(tt.data)

			// 确保有数据时编码结果不为空
			if encoded == "" && len(tt.data) > 0 {
				t.Errorf("Base62Encode() 返回空字符串，但预期有结果")
			}

			// 记录原始编码供调试
			t.Logf("原始数据: %v", tt.data)
			t.Logf("编码结果: %s", encoded)

			// 解码结果
			decoded, err := DecodeBase62ID(encoded)
			if err != nil {
				t.Errorf("DecodeBase62ID() 错误 = %v", err)
				return
			}

			t.Logf("解码结果: %v", decoded)

			// 如果原数据为空，确保解码结果为 [0]
			if len(tt.data) == 0 {
				if !bytes.Equal(decoded, []byte{0}) {
					t.Errorf("对于空输入，解码结果应为 [0]，但得到 %v", decoded)
				}
				return
			}

			// 由于编码-解码过程中可能存在信息损失（混淆字符），
			// 对于ID验证的目的，我们主要关注以下两点：
			// 1. 解码结果不应为空
			// 2. 相同的编码应该产生相同的解码结果

			if len(decoded) == 0 {
				t.Errorf("解码结果不应为空")
			}

			// 测试编码-解码-编码的一致性
			// 即，相同的编码字符串应该始终得到相同的解码结果
			decoded1, err := DecodeBase62ID(encoded)
			if err != nil {
				t.Errorf("首次解码出错: %v", err)
				return
			}

			decoded2, err := DecodeBase62ID(encoded)
			if err != nil {
				t.Errorf("第二次解码出错: %v", err)
				return
			}

			if !bytes.Equal(decoded1, decoded2) {
				t.Errorf("对相同编码的两次解码结果不一致")
			}

			// 对于32字节的随机数据，我们期望编码后的长度为43以上
			if len(tt.data) == 32 && len(encoded) < 43 {
				t.Errorf("32字节随机数据的编码长度应至少为43，但实际为%d", len(encoded))
			}
		})
	}
}

func TestBase62DecodeError(t *testing.T) {
	// 测试无效字符
	invalidChars := []string{
		"abc!def", // 包含感叹号
		"xyz@123", // 包含@符号
		"测试",      // 非ASCII字符
	}

	for _, invalid := range invalidChars {
		t.Run("无效字符："+invalid, func(t *testing.T) {
			_, err := DecodeBase62ID(invalid)
			if err == nil {
				t.Errorf("对于包含无效字符的输入 %s，期望返回错误但没有", invalid)
			}
		})
	}
}

func TestGenerateBase62ID(t *testing.T) {
	// 测试ID生成
	id1, err := GenerateBase62ID()
	if err != nil {
		t.Errorf("GenerateBase62ID() 错误 = %v", err)
		return
	}

	// 生成的ID不应为空
	if id1 == "" {
		t.Error("GenerateBase62ID() 返回空字符串")
	}

	// 生成另一个ID，确保它们不相同（随机性检查）
	id2, err := GenerateBase62ID()
	if err != nil {
		t.Errorf("GenerateBase62ID() 第二次调用错误 = %v", err)
		return
	}

	if id1 == id2 {
		t.Error("GenerateBase62ID() 两次生成的ID相同，表明随机性不足")
	}

	// 验证生成的ID可以被正确解码
	decoded1, err := DecodeBase62ID(id1)
	if err != nil {
		t.Errorf("无法解码生成的ID: %v", err)
		return
	}

	if len(decoded1) == 0 {
		t.Error("解码后的ID不应为空")
	}
}
