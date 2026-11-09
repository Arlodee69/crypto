package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"

	point4 "cryptography/lab1/point_4"
	point5 "cryptography/lab1/point_5"
)

func main() {
	output := flag.String("out", "demo_output", "каталог результатов")
	flag.Parse()
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	key := []byte{0x13, 0x34, 0x57, 0x79, 0x9b, 0xbc, 0xdf, 0xf1}

	fmt.Println("DES: проверка массивов")
	if err := point5.TestBytes(ctx, point4.NewDESCipher(), key, os.Stdout); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}

	if err := os.MkdirAll(*output, 0755); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	dir, err := os.MkdirTemp(*output, "des-demo-")
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	fmt.Println("DES: проверка файлов")
	if err := point5.TestFiles(ctx, point4.NewDESCipher(), key, dir, flag.Args(), os.Stdout); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	fmt.Println("Все проверки DES пройдены. Результаты:", dir)
}
