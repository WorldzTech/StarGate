package sg

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"

	"github.com/zeebo/xxh3"
	"golang.org/x/crypto/hkdf"
)

const StateLen = 512
const BlockSize = 64

func DeriveStateFromKey(keyBytes, nonceBytes []byte) ([]byte, error) {
	// 1. Инициализация HKDF: используем SHA-512 как базовую функцию.
	// 'salt' (соль) - должна быть уникальной для каждого вызова (nonce идеально подходит).
	// 'info' - контекстная информация (можно использовать пустую строку или название генератора).

	// hkdf.New возвращает io.Reader
	h := hkdf.New(sha512.New, keyBytes, nonceBytes, []byte("StarGate Initial State"))

	// 2. Растягивание ключа: Читаем необходимое количество байтов (512)
	state := make([]byte, StateLen)

	// Чтение 512 байт из генератора HKDF
	n, err := io.ReadFull(h, state)
	if err != nil || n != StateLen {
		return nil, err
	}

	return state, nil
}

func GenKey256() (string, error) {
	key := make([]byte, 256)
	_, err := rand.Read(key)
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(key), nil
}

func GenNonce() (string, error) {
	key := make([]byte, 8)
	_, err := rand.Read(key)
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(key), nil
}

type Waver struct {
	Matrix                        [][]byte
	Nonce                         string
	X                             int
	Y                             int
	OffsetSum                     int
	LastPool                      *SizedPool
	Gates                         []*MatrixGate
	N                             int
	matrixHash                    uint64
	hashEvery                     int
	ReinitMode                    bool
	reinitEvery                   int
	oneByOneMode                  bool
	blockIndex                    int
	currentBlock                  []byte
	currentBlockBeforePostGateMix []byte
	CORR_TEST_MODE                bool
}

func NewWaver(key, nonce string, corrTestMode bool) (*Waver, error) {
	workWithKey := key
	if key == "" {
		k, err := GenKey256()

		if err != nil {
			return nil, err
		}

		fmt.Println("Key:", k)
		workWithKey = k
	}

	// Hashing key to work
	bytes, err := DeriveStateFromKey([]byte(workWithKey), []byte(nonce))

	if err != nil {
		return nil, err
	}

	var matrix [][]byte
	for i := 0; i < 16; i++ {
		row := make([]byte, 16)
		copy(row, bytes[i*16:(i+1)*16])
		matrix = append(matrix, row)
	}

	hash := sha256.Sum256([]byte(key))

	x := int(hash[0] % 16)
	y := int(hash[1] % 16)

	var gates []*MatrixGate

	bytes = bytes[256:]
	for i := range 16 {
		gate := NewMatrixGate(bytes[i*16 : (i+1)*16])
		gates = append(gates, gate)
	}

	if nonce == "" {
		nonce, err = GenNonce()
		if err != nil {
			return nil, err
		}
		fmt.Printf("Nonce: %s\n", nonce)
	}

	w := &Waver{
		Matrix:         matrix,
		Nonce:          nonce,
		X:              x,
		Y:              y,
		Gates:          gates,
		LastPool:       &SizedPool{Size: 8},
		hashEvery:      1,
		reinitEvery:    256,
		ReinitMode:     false,
		CORR_TEST_MODE: corrTestMode,
	}

	err = w.ApplyNonce()

	if err != nil {
		return nil, err
	}

	w.getMatrixHash()
	w.WarmUp(10000)
	// log.Println(w.N)

	return w, nil
}

func (w *Waver) WarmUp(n int) {
	for range n {
		if w.CORR_TEST_MODE {
			w.GetNext_CORR_TEST()
		} else {
			w.GetNext()
		}
	}
}

func (w *Waver) PassThroughGates(val byte) byte {
	// Выбираем гейт на основе текущей суммы смещения
	gateIndex := w.OffsetSum % len(w.Gates) // или w.Matrix[x][y] % 16

	gate := w.Gates[gateIndex]
	val = gate.PassValue(val, w.OffsetSum)

	return val // Убрали внешний цикл, остался 1 проход
}

func (w *Waver) MixByte(val byte) byte {
	toMixWith := w.LastPool.State

	if len(toMixWith) < 2 {
		return val
	}

	v := int(val)

	for i := 1; i < len(toMixWith); i++ {
		a := int(toMixWith[i])
		b := int(toMixWith[i-1])

		rotV := ((v << 3) | (v >> 5)) & 0xff
		rotA := ((a << 1) | (a >> 7)) & 0xff

		v = (rotV + rotA + b) & 0xff
	}

	return byte(v)
}

func (w *Waver) shiftColumnBitsLeft(col int) {
	for i := 0; i < 16; i++ {
		val := w.Matrix[i][col]
		w.Matrix[i][col] = ((val << 1) | (val >> 7)) & 0xFF
	}
}

func (w *Waver) getMatrixHash() {
	flat := make([]byte, 0, 256)
	for i := 0; i < 16; i++ {
		flat = append(flat, w.Matrix[i]...) // добавляем всю строку
	}
	w.matrixHash = xxh3.Hash(flat)
}

func (w *Waver) GetPosFromMatrixState() (byte, byte) {
	if w.N%w.hashEvery == 0 {
		w.getMatrixHash()
	}
	return byte(w.matrixHash>>0) % 16, byte(w.matrixHash>>8) % 16
}

func (w *Waver) XORCross(x, y int) {
	val := w.Matrix[x][y]

	for i := 0; i < 16; i++ {
		if i != int(x) {
			w.Matrix[i][y] ^= val
		}
	}

	for i := 0; i < 16; i++ {
		if i != int(y) {
			w.Matrix[x][i] ^= val
		}
	}

	w.Matrix[x][y] = val

	for i, j := 0, 15; i < j; i, j = i+1, j-1 {
		w.Matrix[x][i], w.Matrix[x][j] = w.Matrix[x][j], w.Matrix[x][i]
	}

	col := make([]byte, 16)
	for i := 0; i < 16; i++ {
		col[i] = ((w.Matrix[i][y] << 1) | (w.Matrix[i][y] >> 7)) & 0xff
	}
	for i := 0; i < 16; i++ {
		w.Matrix[i][y] = col[i]
	}
}

func (w *Waver) ReinitFromHash() {
	w.getMatrixHash()
	seed := w.matrixHash

	for i := 0; i < 16; i++ {
		h1 := xxh3.HashSeed([]byte{byte(i)}, seed)
		binary.LittleEndian.PutUint64(w.Matrix[i][:8], h1)

		h2 := xxh3.HashSeed([]byte{byte(i + 100)}, seed^h1)
		binary.LittleEndian.PutUint64(w.Matrix[i][8:], h2)
	}
}

func (w *Waver) LightShuffle() {
	// Быстрое, но мощное перемешивание
	for r := 0; r < 4; r++ {
		// Вызываем XORCross с новым, непредсказуемым смещением
		newX := w.OffsetSum % 16
		newY := (w.OffsetSum ^ int(w.Matrix[newX][r])) % 16
		w.XORCross(newX, newY)
		w.shiftColumnBitsLeft(int(newY))
	}
}

func (w *Waver) GetNext() byte {
	return w.getByteFromBlock()
}

func (w *Waver) GetNext_CORR_TEST() (byte, byte) {
	return w.getByteFromBlock_CORR_TEST()
}

func (w *Waver) ApplyNonce() error {
	if len(w.Nonce) != 16 {
		return errors.New("nonce must be 16 characters length. Nounce: " + w.Nonce)
	}

	nonceBytes := []byte(w.Nonce)

	idx := 0
	for i := 0; i < 16; i++ {
		for j := 0; j < 16; j++ {
			if idx < len(nonceBytes) {
				w.Matrix[i][j] ^= nonceBytes[idx]
				idx++
			} else {
				idx = 0
			}
		}
	}

	for g := 0; g < len(w.Gates); g++ {
		for i := 0; i < 4; i++ {
			for j := 0; j < 4; j++ {
				if idx < len(nonceBytes) {
					w.Gates[g].Matrix[i][j] ^= nonceBytes[idx]
					idx++
				} else {
					idx = 0
				}
			}
		}
	}

	return nil
}

func (w *Waver) refillBlock() {
	if len(w.currentBlock) > 0 {
		return
	}

	// Используем текущее состояние для выбора координат для XORCross
	x := w.Y % 16
	y := w.X % 16

	// 1. УСИЛЕННОЕ ПЕРЕМЕШИВАНИЕ СОСТОЯНИЯ (Увеличиваем до 8 раундов)
	// Это должно размазать однобитовый флип ключа по всей матрице
	for r := 0; r < 8; r++ { // 🚨 Увеличено с 4 до 8
		w.XORCross((x+r)%16, (y-r+16)%16)
	}

	// 1.5. УСИЛЕННАЯ МОДИФИКАЦИЯ СОСТОЯНИЯ ЧЕРЕЗ GATES
	// Применяем Gate ко всем 4 строкам, из которых формируется блок
	gateIndex := w.blockIndex % len(w.Gates)
	gate := w.Gates[gateIndex]

	// Применяем Gate к строкам 0, 1, 2, 3 (которые будут извлечены)
	for r := 0; r < 4; r++ {
		row := w.Matrix[r]
		for i := 0; i < 16; i++ {
			// Используем индекс строки (r) и байта (i) для разнообразия
			// Это гарантирует, что нелинейность Гейта попадает прямо в выходные байты
			row[i] = gate.PassValue(row[i], w.OffsetSum+i+r+w.blockIndex)
		}
	}

	// 2. ИЗВЛЕЧЕНИЕ БЛОКА
	w.currentBlock = make([]byte, BlockSize)

	// Извлекаем 64 байта из верхних 4 строк
	copy(w.currentBlock, w.Matrix[0][:])
	copy(w.currentBlock[16:], w.Matrix[1][:])
	copy(w.currentBlock[32:], w.Matrix[2][:])
	copy(w.currentBlock[48:], w.Matrix[3][:])

	// 3. ПОСТ-СМЕШИВАНИЕ БЛОКА (Финальная нелинейность)
	// Используем СЛЕДУЮЩИЙ гейт
	postMixGateIndex := (w.blockIndex + 1) % len(w.Gates)
	postMixGate := w.Gates[postMixGateIndex]

	for i := 0; i < BlockSize; i++ {
		// Быстрая нелинейность с OffsetSum и другим Gate
		w.currentBlock[i] = w.currentBlock[i] ^ byte(w.OffsetSum)
		// Финальная нелинейная обработка
		w.currentBlock[i] = postMixGate.PassValue(w.currentBlock[i], w.blockIndex)
	}

	w.blockIndex++

	w.ReinitFromHash()
	// 4. Обновление состояния: смена позиции для следующего раунда
	w.changePosition()
}

func (w *Waver) refillBlock_CORR_TEST() {
	if len(w.currentBlock) > 0 {
		return
	}

	// Используем текущее состояние для выбора координат для XORCross
	x := w.Y % 16
	y := w.X % 16

	// 1. УСИЛЕННОЕ ПЕРЕМЕШИВАНИЕ СОСТОЯНИЯ (Увеличиваем до 8 раундов)
	// Это должно размазать однобитовый флип ключа по всей матрице
	for r := 0; r < 8; r++ { // 🚨 Увеличено с 4 до 8
		w.XORCross((x+r)%16, (y-r+16)%16)
	}

	// 1.5. УСИЛЕННАЯ МОДИФИКАЦИЯ СОСТОЯНИЯ ЧЕРЕЗ GATES
	// Применяем Gate ко всем 4 строкам, из которых формируется блок
	gateIndex := w.blockIndex % len(w.Gates)
	gate := w.Gates[gateIndex]

	// Применяем Gate к строкам 0, 1, 2, 3 (которые будут извлечены)
	for r := 0; r < 4; r++ {
		row := w.Matrix[r]
		for i := 0; i < 16; i++ {
			// Используем индекс строки (r) и байта (i) для разнообразия
			// Это гарантирует, что нелинейность Гейта попадает прямо в выходные байты
			row[i] = gate.PassValue(row[i], w.OffsetSum+i+r+w.blockIndex)
		}
	}

	// 2. ИЗВЛЕЧЕНИЕ БЛОКА
	w.currentBlock = make([]byte, BlockSize)

	// Извлекаем 64 байта из верхних 4 строк
	copy(w.currentBlock, w.Matrix[0][:])
	copy(w.currentBlock[16:], w.Matrix[1][:])
	copy(w.currentBlock[32:], w.Matrix[2][:])
	copy(w.currentBlock[48:], w.Matrix[3][:])

	// 3. ПОСТ-СМЕШИВАНИЕ БЛОКА (Финальная нелинейность)
	// Используем СЛЕДУЮЩИЙ гейт
	postMixGateIndex := (w.blockIndex + 1) % len(w.Gates)
	postMixGate := w.Gates[postMixGateIndex]

	w.currentBlockBeforePostGateMix = make([]byte, BlockSize)
	copy(w.currentBlockBeforePostGateMix, w.currentBlock)
	for i := 0; i < BlockSize; i++ {
		// Быстрая нелинейность с OffsetSum и другим Gate
		w.currentBlock[i] = w.currentBlock[i] ^ byte(w.OffsetSum)
		// Финальная нелинейная обработка
		w.currentBlock[i] = postMixGate.PassValue(w.currentBlock[i], w.blockIndex)
	}

	w.blockIndex++

	w.ReinitFromHash()
	// 4. Обновление состояния: смена позиции для следующего раунда
	w.changePosition()
}

func (w *Waver) changePosition() {
	stepDX := (w.OffsetSum ^ int(w.Matrix[(w.X+1)%16][w.Y])) % 16
	stepYX := (w.OffsetSum + int(w.Matrix[w.X][(w.Y+1)%16])) % 16
	w.X = (w.X + stepDX) % 16
	w.Y = (w.Y + stepYX) % 16
}

func (w *Waver) getByteFromBlock() byte {
	if len(w.currentBlock) == 0 {
		w.refillBlock()
	}

	// 🚨 ИДЕАЛЬНАЯ АМОРТИЗАЦИЯ: ТОЛЬКО ВЫДАЕМ БАЙТ
	r := w.currentBlock[0]

	// 🚨 УДАЛЕНЫ дорогие вызовы: PassThroughGates и MixByte.
	// Вся их работа выполнена один раз в refillBlock.

	w.OffsetSum += int(r)
	w.currentBlock = w.currentBlock[1:]

	w.N++

	return r
}

func (w *Waver) getByteFromBlock_CORR_TEST() (byte, byte) {
	if len(w.currentBlock) == 0 {
		w.refillBlock_CORR_TEST()
	}

	// 🚨 ИДЕАЛЬНАЯ АМОРТИЗАЦИЯ: ТОЛЬКО ВЫДАЕМ БАЙТ
	r1 := w.currentBlock[0]
	r2 := w.currentBlockBeforePostGateMix[0]

	// 🚨 УДАЛЕНЫ дорогие вызовы: PassThroughGates и MixByte.
	// Вся их работа выполнена один раз в refillBlock.

	w.OffsetSum += int(r1)
	w.currentBlock = w.currentBlock[1:]
	w.currentBlockBeforePostGateMix = w.currentBlockBeforePostGateMix[1:]

	w.N++

	return r1, r2
}
