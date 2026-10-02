package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"

	"cryptography/lab1/point_5"
)

func main() {
	output := flag.String("out", "demo_output", "каталог результатов")
	flag.Parse()
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	dir, err := point5.Run(ctx, *output, flag.Args(), os.Stdout)
	if dir != "" {
		fmt.Println("Результаты:", dir)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
