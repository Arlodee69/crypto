package main

import (
	"context"
	"encoding/hex"
	"flag"
	"fmt"
	"os"
	"os/signal"

	point5 "cryptography/lab1/point_5"
	point6 "cryptography/lab1/point_6"
)

func main() {
	output := flag.String("out", "demo_output", "каталог результатов")
	keyHex := flag.String("key", "30313233343536373839616263646566", "ключ DEAL в hex: 32, 48 или 64 цифры")
	flag.Parse()
	key, err := hex.DecodeString(*keyHex)
	if err != nil {
		fmt.Fprintln(os.Stderr, "неверная hex-запись ключа:", err)
		os.Exit(1)
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()

	fmt.Println("DEAL: проверка массивов")
	if err := point5.TestBytes(ctx, point6.NewDEALCipher(), key, os.Stdout); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	if err := os.MkdirAll(*output, 0755); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	dir, err := os.MkdirTemp(*output, "deal-demo-")
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	fmt.Println("DEAL: проверка файлов")
	if err := point5.TestFiles(ctx, point6.NewDEALCipher(), key, dir, flag.Args(), os.Stdout); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	fmt.Println("Все проверки DEAL пройдены. Результаты:", dir)
}
