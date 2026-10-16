package main

import (
	"context"
	"encoding/hex"
	"flag"
	"fmt"
	"os"
	"os/signal"

	"cryptography/lab1/point_7"
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
	dir, err := point7.RunWithKey(ctx, *output, flag.Args(), os.Stdout, key)
	if dir != "" {
		fmt.Println("Результаты:", dir)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
