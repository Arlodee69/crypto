# Пункт 3 — сеть Фейстеля

`FeistelCipher` реализует интерфейс `point2.SymmetricCipher`. Конструктор принимает размер полного блока в байтах, число раундов и реализации интерфейсов `point2.KeyExpander` и `point2.RoundTransformer` из пункта 2.

Размер блока должен быть положительным и чётным, число раундов — положительным. Генератор должен вернуть ровно по одному ключу на раунд; ограничения на длину исходного и раундовых ключей определяют переданные реализации.

Каждый раунд вычисляет `L, R = R, L XOR F(R, K)`. Функция `F` получает половину блока и раундовый ключ, возвращает массив размером в половину блока. После последнего раунда результат записывается как `R || L`. Дешифрование выполняет те же раунды с ключами в обратном порядке, поэтому обратимость `F` не требуется. Эта договорённость о финальной перестановке позволяет далее использовать сеть для DES.

## Шпаргалка: как работает сеть

Код ниже — фрагменты [feistel_cipher.go](feistel_cipher.go); проверки ошибок опущены для краткости. `L` и `R` — левая и правая половины, `K` — ключ текущего раунда, `F` — переданная раундовая функция, `XOR` в Go — оператор `^`.

**Подготовка ключей (`SetKey`).** Сеть вызывает генератор, переданный в конструктор, и сохраняет копии полученных ключей в `c.roundKeys`:

```go
keys, err := c.keyExpander.ExpandKey(append([]byte(nil), key...))
```

**Разделение блока (`transform`).** Например, блок 8 байт → `L` 4 байта и `R` 4 байта:

```go
half := c.blockSize / 2
left := append([]byte(nil), block[:half]...)
right := append([]byte(nil), block[half:]...)
```

**Один раунд: `(L, R) → (R, L XOR F(R, K))`.** Сначала вычисляется F от старой правой половины, затем XOR со старой левой, затем обмен:

```go
transformed, err := c.transformer.Transform(
    append([]byte(nil), right...),
    append([]byte(nil), c.roundKeys[keyIndex]...),
)
for i := range left {
    left[i] ^= transformed[i] // L = старая L XOR F(старой R, K)
}
left, right = right, left     // новая L = старая R; новая R = результат XOR
```

`append([]byte(nil), slice...)` создаёт копию среза. Сама сеть не задаёт алгоритм F: его выполняет объект из поля `transformer`.

**После всех раундов: `R || L`.** Здесь `||` означает соединение половин:

```go
result := make([]byte, c.blockSize)
copy(result, right)
copy(result[half:], left)
```

**Дешифрование:** тот же цикл, но ключи берутся от последнего к первому:

```go
keyIndex := round
if decrypt {
    keyIndex = c.rounds - 1 - round
}
```

Почему работает: `A XOR B XOR B = A`. Из новых половин можно восстановить старые: `старая R = новая L`, `старая L = новая R XOR F(новой L, K)`. Обратная функция F не нужна. Благодаря выходу `R || L` весь блок расшифровывается тем же циклом с обратным порядком ключей.

## Использование

Пример подключения своих реализаций `expander` и `transformer`:

```go
import (
    "context"
    "cryptography/lab1/point_2"
    "cryptography/lab1/point_3"
)

// expander и transformer — ваши реализации интерфейсов из point2.
cipher, err := point3.NewFeistelCipher(8, 16, expander, transformer)
if err != nil {
    return err
}
c, err := point2.NewCipherContext(cipher, key, point2.CBC, point2.PKCS7, nil)
if err != nil {
    return err
}
iv := c.IV() // сохранить для последующего дешифрования
_ = iv
encrypted := <-c.Encrypt(context.Background(), []byte("Пример текста"))
if encrypted.Err != nil {
    return encrypted.Err
}
decrypted := <-c.Decrypt(context.Background(), encrypted.Data)
if decrypted.Err != nil {
    return decrypted.Err
}
// decrypted.Data содержит исходный текст.
```

Для обработки отдельного блока вызовите `cipher.SetKey(key)`, затем `EncryptBlock` или `DecryptBlock`. Эти методы принимают ровно один полный блок; набивку и режимы обеспечивает контекст пункта 2.

Исходные данные и ключи копируются. Неудачный `SetKey` сохраняет ранее установленный ключ. Блочные операции можно вызывать параллельно, если переданная `RoundTransformer` поддерживает одновременные вызовы. `SetKey` вызывается до обработки данных. Сам генератор и раундовая функция должны оставаться настроенными в течение использования шифра.

Из каталога `lab1`: `go test ./point_3`.
