// Демонстрация всех функций из пункта 1: go run ./cmd/point1_demo
package main

import (
	"fmt"
	"log"
	"math/big"

	point1 "cryptography/lab2/point_1"
)

func main() {
	// Сервис не хранит состояние. Аргументы функций можно менять прямо здесь.
	s := point1.Service{}

	// Обычный алгоритм Евклида.
	a, b := big.NewInt(240), big.NewInt(46)
	fmt.Printf("Евклид: НОД(%s, %s) = %s\n", a, b, s.GCD(a, b))

	// Расширенный алгоритм Евклида и соотношение Безу: a*x + b*y = НОД(a, b).
	g, x, y := s.ExtendedGCD(a, b)
	fmt.Printf("Расширенный Евклид: НОД = %s, x = %s, y = %s\n", g, x, y)
	fmt.Printf("Безу: %s*(%s) + %s*(%s) = %s\n", a, x, b, y,
		new(big.Int).Add(new(big.Int).Mul(a, x), new(big.Int).Mul(b, y)))

	// Бинарный алгоритм Евклида.
	fmt.Printf("Бинарный Евклид: НОД(%s, %s) = %s\n", a, b, s.BinaryGCD(a, b))

	// Символ Лежандра: знаменатель должен быть простым числом.
	legendre, err := s.Legendre(big.NewInt(5), big.NewInt(11))
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("Символ Лежандра (5/11) = %d\n", legendre)

	// Символ Якоби: знаменатель должен быть положительным нечётным числом.
	jacobi, err := s.Jacobi(big.NewInt(5), big.NewInt(21))
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("Символ Якоби (5/21) = %d\n", jacobi)

	// Быстрое возведение в степень по модулю.
	power, err := s.ModPow(big.NewInt(4), big.NewInt(13), big.NewInt(497))
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("4^13 mod 497 = %s\n", power)

	// Функция Эйлера по определению: количество взаимно простых с 36 чисел.
	definition, err := s.TotientDefinition(36)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("Функция Эйлера по определению: φ(36) = %d\n", definition)

	// Функция Эйлера через разложение 36 = 2^2 * 3^2.
	factorization, err := s.TotientFactorization(big.NewInt(36))
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("Функция Эйлера через разложение: φ(36) = %s\n", factorization)

	// Функция Эйлера через сумму с косинусами из задания (ДПФ).
	fourier, err := s.TotientFourier(36)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("Функция Эйлера через ДПФ: φ(36) = %d\n", fourier)

	// Функция Кармайкла через разложение 561 = 3 * 11 * 17.
	lambda, err := s.Carmichael(big.NewInt(561))
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("Функция Кармайкла: λ(561) = %s\n", lambda)
}
