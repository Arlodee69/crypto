# Пункт 4 — DES

Самостоятельная реализация DES по [NIST FIPS 46-3](https://csrc.nist.gov/pubs/fips/46-3/final), без готовых криптографических алгоритмов из библиотек.

- `DESCipher` реализует `point2.SymmetricCipher`: блок 8 байт, ключ 8 байт, 16 раундов.
- `DESKeyExpander` реализует `point2.KeyExpander`: PC-1, сдвиги 28-битных половин, PC-2; выдаёт 16 ключей по 6 байт.
- `DESRoundTransformer` реализует `point2.RoundTransformer`: расширение E, XOR, S-блоки, P.
- Все перестановки выполняет `point1.Permute`; раунды и обратный порядок ключей выполняет `point3.FeistelCipher`.
- Начальная и конечная перестановки применяются вокруг сети Фейстеля. Её выход уже имеет порядок `R || L`.

Биты чётности ключа исключаются PC-1 и не проверяются. `SetKey` вызывается до параллельной обработки блоков. Входные массивы не изменяются, результаты возвращаются в новых массивах. Ошибочный ключ сохраняет предыдущую настройку.

## Шпаргалка: структура и путь блока

В [des.go](des.go) три отдельных типа. `DESCipher` содержит `FeistelCipher` в поле `network`; `DESKeyExpander` генерирует ключи; `DESRoundTransformer` вычисляет F. Конструктор соединяет их:

```go
network, err := point3.NewFeistelCipher(
    BlockSize, Rounds, DESKeyExpander{}, DESRoundTransformer{},
)
```

Пустые структуры имеют методы, хотя не хранят полей. Сеть сохраняет их в интерфейсах и вызывает `ExpandKey` и `Transform`. `DESCipher.transform` выполняет перестановки вокруг сети; `FeistelCipher.transform` выполняет раунды; `DESRoundTransformer.Transform` выполняет только F одного раунда.

```text
Блок 64 бита → IP (64) → L и R по 32 бита
             → 16 раундов Фейстеля → R16 || L16 (64) → IP⁻¹ (64)
```

В `DESCipher.transform` это происходит здесь (в фрагментах ниже проверки ошибок опущены):

```go
permuted, err := permute(block, initialPermutation[:]) // IP: 64 → 64
// В ветке шифрования:
result, err = c.network.EncryptBlock(permuted)         // 16 раундов
return permute(result, finalPermutation[:])           // IP⁻¹: 64 → 64
```

При дешифровании вместо `EncryptBlock` вызывается `c.network.DecryptBlock(permuted)`: сеть использует ключи в обратном порядке. Начальная и конечная перестановки остаются на тех же местах.

Все таблицы находятся в [tables.go](tables.go). Один элемент таблицы выбирает один входной бит; количество элементов определяет количество значащих выходных битов. Переносы строк не делят результат на группы. `Permute` возвращает целые байты с округлением вверх; в DES все эти таблицы дают целое число байт. Нумерация — от старшего бита, начиная с 1.

## Расширение ключа — `DESKeyExpander.ExpandKey`

```text
Ключ 64 бита → PC-1 (56) → C и D по 28 бит
Каждый раунд: сдвиг C и D на 1 или 2 → C || D (56) → PC-2 (48)
Результат: 16 ключей, каждый 48 бит = 6 байт
```

**PC-1: 64 → 56 бит.** Переставляет биты и исключает 8 битов чётности:

```go
selected, err := permute(key, keyPermutation[:]) // 56 элементов → 7 байт
var value uint64
for _, b := range selected {
    value = value<<8 | uint64(b) // собираем семь байт в число
}
left, right := uint32(value>>28), uint32(value&0xfffffff)
// left = C, верхние 28 бит; right = D, нижние 28 бит
```

`value<<8` освобождает справа один байт, `| b` добавляет его: байты `12 34 56` дают число `0x123456`. Тип `uint64` имеет 64 позиции, но здесь заняты данными только младшие 56.

**Циклический сдвиг двух половин.** Биты, вышедшие слева, возвращаются справа:

```go
for i, shift := range keyShifts {
    left = ((left << shift) | (left >> (28 - shift))) & 0xfffffff
    right = ((right << shift) | (right >> (28 - shift))) & 0xfffffff
    // Далее в этом же цикле выполняется PC-2.
}
```

`<< shift` сдвигает влево, `>> (28-shift)` переносит старшие биты в конец, `|` соединяет части, маска `0xfffffff` оставляет 28 бит. Например, на четырёх битах сдвиг на 1: `1001 → 0011`. Следующий раунд сдвигает результат предыдущего.

**PC-2: 56 → 48 бит.** Внутри того же цикла половины соединяются и выбираются 48 бит:

```go
var packed [8]byte
binary.BigEndian.PutUint64(packed[:], (uint64(left)<<28|uint64(right))<<8)
keys[i], err = permute(packed[:7], compressionPermutation[:])
```

`left<<28 | right` соединяет половины в 56-битное число. Последний `<<8` размещает его в первых семи байтах восьмибайтового массива: `[7 байт данных][00]`. Поэтому `packed[:7]` содержит все 56 бит, а PC-2 выбирает 48. Ключи готовятся при `SetKey`, а затем используются для всех блоков.

## Раундовая функция — `DESRoundTransformer.Transform`

```text
R (32 бита) → E (48) → XOR с K (48)
           → 8 S-блоков, каждый 6 → 4 бита (всего 32) → P (32)
```

**Расширение E: 32 → 48 бит.** Некоторые входные биты выбираются повторно:

```go
expanded, err := permute(block, expansionPermutation[:]) // 48 элементов → 6 байт
```

Здесь `block` — правая половина, 4 байта. **XOR с ключом: 48 → 48 бит**; шесть полученных байтов собираются в число:

```go
var value uint64
for i, b := range expanded {
    value = value<<8 | uint64(b^roundKey[i])
}
```

`^` — XOR соответствующих байтов. Шесть итераций добавляют по 8 бит: в `uint64` старшие 16 позиций нулевые, младшие 48 содержат результат.

**S-блоки: 48 → 32 бита.** Из числа выделяются восемь групп по 6 бит; каждая таблица возвращает 4 бита:

```go
var substituted uint32
for i := 0; i < 8; i++ {
    group := byte(value>>uint(42-6*i)) & 0x3f
    row := (group&0x20)>>4 | group&1
    column := (group >> 1) & 0xf
    substituted = substituted<<4 | uint32(sBoxes[i][row][column])
}
```

Сдвиги `42, 36, …, 0` выбирают группы слева направо; `0x3f` оставляет 6 бит. Для группы `b1 b2 b3 b4 b5 b6` строка — крайние биты `b1b6`, столбец — средние `b2b3b4b5`. Например, `101011`: строка `11₂ = 3`, столбец `0101₂ = 5`. Результаты подстановок добавляются по 4 бита: `8 × 4 = 32`.

**Перестановка P: 32 → 32 бита.** Записываем число в 4 байта и переставляем биты:

```go
var packed [4]byte
binary.BigEndian.PutUint32(packed[:], substituted)
return permute(packed[:], roundPermutation[:])
```

Это результат `F(R, K)`. Сеть Фейстеля затем выполняет `L XOR F(R, K)` и обмен половин — см. [шпаргалку пункта 3](../point_3/README.md).

## Использование

```go
cipher := point4.NewDESCipher()
err := cipher.SetKey([]byte{0x13, 0x34, 0x57, 0x79, 0x9b, 0xbc, 0xdf, 0xf1})
if err != nil {
    return err
}
encrypted, err := cipher.EncryptBlock([]byte{0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef})
if err != nil {
    return err
}
// encrypted: 85 E8 13 54 0F 0A B4 05
decrypted, err := cipher.DecryptBlock(encrypted)
```

Для произвольной длины и файлов передавайте `NewDESCipher()` в `point2.NewCipherContext`; контекст сам вызывает `SetKey`. Пример — в [пункте 5](../point_5/README.md).
