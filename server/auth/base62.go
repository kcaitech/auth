package auth

import (
	"crypto/rand"
	"fmt"
	"math/big"
)

// 62进制字符集（0-9, a-z, A-Z）
const base62Chars = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"

// base62Encode 将字节切片编码为62进制字符串
func Base62Encode(data []byte) string {
	// 计算需要的容量：一个字节最多需要2个62进制字符
	capacity := len(data) * 2
	result := make([]byte, 0, capacity)

	// 将字节切片转换为一个大整数
	var n big.Int
	n.SetBytes(data)

	// 62进制基数
	base := big.NewInt(62)
	zero := big.NewInt(0)
	mod := new(big.Int)

	// 进行62进制转换
	for n.Cmp(zero) > 0 {
		n.DivMod(&n, base, mod)
		result = append(result, base62Chars[mod.Int64()])
	}

	// 添加剩余字节的混淆编码，确保固定长度
	// 即使输入的低字节全为0，仍能保持一定长度
	for i := 0; i < len(data)/8 && len(result) < 43; i++ {
		result = append(result, base62Chars[data[i]%62])
	}

	// 反转结果（因为我们是从低位到高位添加的）
	for i, j := 0, len(result)-1; i < j; i, j = i+1, j-1 {
		result[i], result[j] = result[j], result[i]
	}

	return string(result)
}

func GenerateBase62ID() (string, error) {
	b := make([]byte, 32)
	_, err := rand.Read(b)
	if err != nil {
		return "", fmt.Errorf("生成随机字节失败: %w", err)
	}
	// 使用62进制编码（数字+大小写字母）来缩短ID长度
	return Base62Encode(b), nil
}