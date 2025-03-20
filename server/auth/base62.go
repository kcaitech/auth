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

// Base62Decode 将62进制字符串解码为字节切片
// 注意：由于Base62Encode使用了混淆算法，这个解码函数可能无法完全还原原始数据
// 但对于作为ID使用的情况，这个解码是足够的
func DecodeBase62ID(id string) ([]byte, error) {
	// 如果输入为空，返回默认值
	if id == "" {
		return []byte{0}, nil
	}

	// 创建62进制字符到值的映射
	charToVal := make(map[byte]int, 62)
	for i := 0; i < len(base62Chars); i++ {
		charToVal[base62Chars[i]] = i
	}

	// 建立大整数用于计算
	res := new(big.Int).SetInt64(0)
	base := new(big.Int).SetInt64(62)

	// 由于Base62Encode函数在编码时添加了混淆字符，完全精确的解码是困难的
	// 我们这里主要解码主要的数字部分

	// 遍历ID字符串，从高位到低位
	for i := 0; i < len(id); i++ {
		// 获取当前字符的值
		val, ok := charToVal[id[i]]
		if !ok {
			return nil, fmt.Errorf("无效的Base62字符: %c", id[i])
		}

		// 乘以基数并加上当前值
		res.Mul(res, base)
		res.Add(res, big.NewInt(int64(val)))
	}

	// 将大整数转换回字节切片
	bytes := res.Bytes()

	// 如果结果为空（可能是因为输入为"0"），返回一个零字节
	if len(bytes) == 0 {
		return []byte{0}, nil
	}

	return bytes, nil
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

func GenerateByteID() ([]byte, error) {
	b := make([]byte, 32)
	_, err := rand.Read(b)
	if err != nil {
		return nil, fmt.Errorf("生成随机字节失败: %w", err)
	}
	return b, nil
}

// generateBase62String 生成指定长度的随机62进制字符串
// func generateBase62String(length int) string {
// 	result := make([]byte, length)
// 	// 62进制基数
// 	base := big.NewInt(62)

// 	for i := 0; i < length; i++ {
// 		// 生成0-61的随机数
// 		n, err := rand.Int(rand.Reader, base)
// 		if err != nil {
// 			// 如果发生错误，使用简单的回退方法
// 			result[i] = base62Chars[i%62]
// 			continue
// 		}
// 		result[i] = base62Chars[n.Int64()]
// 	}

// 	return string(result)
// }
