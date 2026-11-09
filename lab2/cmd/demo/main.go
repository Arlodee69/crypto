// Command demo demonstrates and checks all four laboratory tasks.
package main

import (
	"bytes"
	"context"
	"flag"
	"fmt"
	"math/big"
	"os"
	"time"

	point1 "cryptography/lab2/point_1"
	point2 "cryptography/lab2/point_2"
	point3 "cryptography/lab2/point_3"
	point4 "cryptography/lab2/point_4"
)

func main() {
	bits := flag.Int("bits", 128, "битовая длина каждого множителя RSA (не модуля)")
	attackBits := flag.Int("attack-bits", 32, "битовая длина множителей уязвимого ключа")
	confidence := flag.Float64("confidence", 0.999999999, "уровень доверия теста в [0.5, 1)")
	testName := flag.String("test", "miller-rabin", "fermat, solovay-strassen или miller-rabin")
	timeout := flag.Duration("timeout", 30*time.Second, "общий таймаут демонстрации")
	flag.Parse()
	kinds := map[string]point3.TestKind{
		"fermat": point3.Fermat, "solovay-strassen": point3.SolovayStrassen, "miller-rabin": point3.MillerRabin,
	}
	kind, ok := kinds[*testName]
	if !ok {
		fmt.Fprintln(os.Stderr, "Неизвестный тест:", *testName)
		os.Exit(1)
	}
	ctx, cancel := context.WithTimeout(context.Background(), *timeout)
	defer cancel()
	if err := run(ctx, kind, *confidence, *bits, *attackBits); err != nil {
		fmt.Fprintln(os.Stderr, "Ошибка проверки:", err)
		os.Exit(1)
	}
}

func run(ctx context.Context, kind point3.TestKind, confidence float64, bits, attackBits int) error {
	if err := point2.ValidateConfidence(confidence); err != nil {
		return err
	}
	if err := arithmeticDemo(); err != nil {
		return err
	}
	if err := primalityDemo(ctx, confidence); err != nil {
		return err
	}
	if err := rsaDemo(ctx, kind, confidence, bits); err != nil {
		return err
	}
	if err := wienerDemo(ctx, confidence, attackBits); err != nil {
		return err
	}
	fmt.Println("\nВсе демонстрационные проверки пройдены.")
	return nil
}

func arithmeticDemo() error {
	fmt.Println("Пункт 1. Stateless-сервис арифметики")
	s := point1.Service{}
	a, b := big.NewInt(-240), big.NewInt(46)
	g, x, y := s.ExtendedGCD(a, b)
	identity := new(big.Int).Add(new(big.Int).Mul(a, x), new(big.Int).Mul(b, y))
	if g.Int64() != 2 || s.GCD(a, b).Cmp(g) != 0 || s.BinaryGCD(a, b).Cmp(g) != 0 || identity.Cmp(g) != 0 {
		return fmt.Errorf("GCD/Bezout mismatch")
	}
	fmt.Printf("НОД(%s, %s) = %s (Евклид, расширенный и бинарный); x=%s, y=%s; ax+by=%s\n", a, b, g, x, y, identity)
	legendre, err := s.Legendre(big.NewInt(5), big.NewInt(11))
	if err != nil || legendre != 1 {
		return fmt.Errorf("Legendre check failed: %v", err)
	}
	jacobi, err := s.Jacobi(big.NewInt(5), big.NewInt(21))
	if err != nil || jacobi != 1 {
		return fmt.Errorf("Jacobi check failed: %v", err)
	}
	fmt.Printf("Лежандр (5/11) = %d; Якоби (5/21) = %d\n", legendre, jacobi)
	power, err := s.ModPow(big.NewInt(4), big.NewInt(13), big.NewInt(497))
	if err != nil || power.Int64() != 445 {
		return fmt.Errorf("modular power check failed: %v", err)
	}
	fmt.Printf("4^13 mod 497 = %s\n", power)
	definition, err := s.TotientDefinition(36)
	if err != nil {
		return err
	}
	factorization, err := s.TotientFactorization(big.NewInt(36))
	if err != nil {
		return err
	}
	fourier, err := s.TotientFourier(36)
	if err != nil {
		return err
	}
	if definition != 12 || factorization.Int64() != 12 || fourier != 12 {
		return fmt.Errorf("three totient methods disagree")
	}
	fmt.Printf("φ(36): по определению=%d; по разложению=%s; через ДПФ=%d\n", definition, factorization, fourier)
	lambda, err := s.Carmichael(big.NewInt(561))
	if err != nil || lambda.Int64() != 80 {
		return fmt.Errorf("Carmichael check failed: %v", err)
	}
	fmt.Printf("λ(561) = %s\n", lambda)
	return nil
}

func primalityDemo(ctx context.Context, confidence float64) error {
	fmt.Printf("\nПункт 2. Тесты простоты; confidence=%.12g\n", confidence)
	tests := []struct {
		name string
		test point2.PrimalityTest
	}{
		{"Ферма", point2.NewFermat(nil)},
		{"Соловей–Штрассен", point2.NewSolovayStrassen(nil)},
		{"Миллер–Рабин", point2.NewMillerRabin(nil)},
	}
	fmt.Printf("%8s %10s %22s %18s\n", "n", "Ферма", "Соловей–Штрассен", "Миллер–Рабин")
	for _, sample := range []struct {
		n     int64
		prime bool
	}{{0, false}, {1, false}, {2, true}, {17, true}, {341, false}, {561, false}, {1105, false}, {65537, true}} {
		results := [3]bool{}
		for i, test := range tests {
			ok, err := test.test.Test(ctx, big.NewInt(sample.n), confidence)
			if err != nil {
				return err
			}
			// A prime can never be rejected. A composite can legitimately pass
			// a probabilistic test, especially with confidence close to 0.5.
			if sample.prime && !ok {
				return fmt.Errorf("%s rejected prime %d", test.name, sample.n)
			}
			results[i] = ok
		}
		fmt.Printf("%8d %10t %22t %18t\n", sample.n, results[0], results[1], results[2])
		for i, ok := range results {
			if ok && !sample.prime {
				fmt.Printf("  %s: наблюдался допустимый вероятностный ложноположительный результат.\n", tests[i].name)
			}
		}
	}
	f, _ := point2.NewFermat(nil).Rounds(big.NewInt(65537), confidence)
	ss, _ := point2.NewSolovayStrassen(nil).Rounds(big.NewInt(65537), confidence)
	mr, _ := point2.NewMillerRabin(nil).Rounds(big.NewInt(65537), confidence)
	fmt.Printf("Итераций для 65537: Ферма=%s; Соловей–Штрассен=%s; Миллер–Рабин=%s\n", f, ss, mr)
	return nil
}

func rsaDemo(ctx context.Context, kind point3.TestKind, confidence float64, bits int) error {
	fmt.Printf("\nПункт 3. RSA; тест=%s, длина каждого множителя=%d бит\n", kind, bits)
	s, err := point3.NewService(kind, confidence, bits)
	if err != nil {
		return err
	}
	keys, err := s.GenerateKeys(ctx)
	if err != nil {
		return err
	}
	fmt.Printf("n=%s\ne=%s; длина d=%d бит\n", keys.Public.N, keys.Public.E, keys.Private.D.BitLen())
	minimum := new(big.Int).Lsh(big.NewInt(1), uint(bits/2))
	if keys.FermatSteps.Cmp(minimum) < 0 {
		return fmt.Errorf("insufficient Fermat distance")
	}
	fmt.Printf("До успеха факторизации Ферма: %s неудачных итераций (минимум %s)\n", keys.FermatSteps, minimum)
	attack, err := (point4.WienerService{}).Attack(keys.Public.E, keys.Public.N)
	if err != nil || attack.Found {
		return fmt.Errorf("protected key recovered by Wiener: %v", err)
	}
	fmt.Println("Атака Винера на защищённый ключ: d не найдено")
	for _, message := range [][]byte{nil, []byte("Лабораторная работа №2: RSA"), {0, 0, 1, 2, 255, 0, 0}} {
		ciphertext, err := s.Encrypt(message)
		if err != nil {
			return err
		}
		decoded, err := s.Decrypt(ciphertext)
		if err != nil || !bytes.Equal(message, decoded) {
			return fmt.Errorf("RSA byte round trip failed: %v", err)
		}
		fmt.Printf("Данные %x -> шифротекст %x -> восстановлено %d байт, совпадение=true\n", message, ciphertext, len(decoded))
	}
	c, err := s.EncryptInteger(big.NewInt(42))
	if err != nil {
		return err
	}
	m, err := s.DecryptInteger(c)
	if err != nil || m.Int64() != 42 {
		return fmt.Errorf("RSA integer round trip failed: %v", err)
	}
	fmt.Printf("Целое: 42 -> %s -> %s\n", c, m)
	regenerated, err := s.GenerateKeys(ctx)
	if err != nil {
		return err
	}
	message := []byte{0, 42, 255, 0}
	ciphertext, err := s.Encrypt(message)
	if err != nil {
		return err
	}
	decoded, err := s.Decrypt(ciphertext)
	if err != nil || !bytes.Equal(message, decoded) {
		return fmt.Errorf("RSA after regeneration failed: %v", err)
	}
	fmt.Printf("Повторная генерация: n=%s; шифрование/дешифрование проверено\n", regenerated.Public.N)
	return nil
}

func wienerDemo(ctx context.Context, confidence float64, bits int) error {
	fmt.Println("\nПункт 4. Атака Винера")
	service := point4.WienerService{}
	known, err := service.Attack(big.NewInt(17993), big.NewInt(90581))
	if err != nil || !known.Found || known.D.Int64() != 5 || known.Phi.Int64() != 89964 {
		return fmt.Errorf("known Wiener vector failed: %v", err)
	}
	fmt.Printf("Контрольный пример: e=17993, n=90581 -> d=%s, φ(n)=%s\n", known.D, known.Phi)
	generator, err := point4.NewVulnerableGenerator(bits, confidence, nil)
	if err != nil {
		return err
	}
	key, err := generator.Generate(ctx)
	if err != nil {
		return err
	}
	attack, err := service.Attack(key.E, key.N)
	if err != nil || !attack.Found || attack.D.Cmp(key.D) != 0 || attack.Phi.Cmp(key.Phi) != 0 {
		return fmt.Errorf("generated vulnerable key not recovered: %v", err)
	}
	fmt.Printf("Сгенерирован уязвимый ключ: e=%s, n=%s\n", key.E, key.N)
	fmt.Printf("Секретные параметры генератора: d=%s, φ(n)=%s\n", key.D, key.Phi)
	fmt.Printf("Найдено атакой: d=%s, φ(n)=%s, p=%s, q=%s\n", attack.D, attack.Phi, attack.P, attack.Q)
	fmt.Println("Вычисленные подходящие дроби k/d для e/n:")
	for i, f := range attack.Convergents {
		mark := ""
		if f.Denominator.Cmp(attack.D) == 0 {
			mark = " <- найденная экспонента"
		}
		fmt.Printf("  %2d: %s/%s%s\n", i, f.Numerator, f.Denominator, mark)
	}
	arithmetic := point1.Service{}
	ciphertext, err := arithmetic.ModPow(big.NewInt(42), key.E, key.N)
	if err != nil {
		return err
	}
	decoded, err := arithmetic.ModPow(ciphertext, attack.D, key.N)
	if err != nil || decoded.Int64() != 42 {
		return fmt.Errorf("recovered exponent failed to decrypt: %v", err)
	}
	fmt.Printf("Дешифрование найденной экспонентой: 42 -> %s -> %s\n", ciphertext, decoded)
	return nil
}
