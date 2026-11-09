package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"

	point5 "cryptography/lab1/point_5"
)

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	message, err := point5.RunBytes(ctx)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	fmt.Println(message)
}
