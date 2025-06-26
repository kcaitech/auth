/*
 * Copyright (c) 2025 KCai Technology (https://kcaitech.com)
 * Licensed under the MIT License.
 */

package main

import (
	"flag"
	"fmt"
	"log"

	"golang.org/x/crypto/bcrypt"
)

func main() {
	// 定义命令行参数
	password := flag.String("password", "", "要哈希的密码")
	cost := flag.Int("cost", bcrypt.DefaultCost, "bcrypt的成本参数，范围是4-31，默认为10")
	flag.Parse()

	// 检查是否提供了密码
	if *password == "" {
		log.Fatal("请提供要哈希的密码，使用-password参数")
	}

	// 验证cost参数
	if *cost < bcrypt.MinCost || *cost > bcrypt.MaxCost {
		log.Fatalf("成本参数必须在%d-%d之间", bcrypt.MinCost, bcrypt.MaxCost)
	}

	// 生成密码哈希
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(*password), *cost)
	if err != nil {
		log.Fatalf("生成密码哈希时出错: %v", err)
	}

	// 打印哈希结果
	fmt.Printf("原始密码: %s\n", *password)
	fmt.Printf("哈希密码: %s\n", string(hashedPassword))
	fmt.Printf("该哈希可以复制到config.yaml文件的\"password\"字段中\n")
}
