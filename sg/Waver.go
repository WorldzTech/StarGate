package sg

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
)

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
	Matrix    [][]byte
	Nonce     string
	X         uint8
	Y         uint8
	OffsetSum uint8
	LastPool  *SizedPool
	Gates     []*MatrixGate
}

func NewWaver(key, nonce string) (*Waver, error) {
	workWithKey := key
	if key == "" {
		k, err := GenKey256()

		if err != nil {
			return nil, err
		}

		fmt.Println("Key:", k)
		workWithKey = k
	}

	bytes, err := hex.DecodeString(workWithKey)

	if err != nil {
		return nil, err
	}

	var matrix [][]byte
	for i := 0; i < 16; i++ {
		row := make([]byte, 16)
		copy(row, bytes[i*16:(i+1)*16])
		matrix = append(matrix, row)
	}

	x := bytes[len(bytes)-2] % 16
	y := bytes[len(bytes)-1] % 16

	var gates []*MatrixGate

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
		Matrix:   matrix,
		Nonce:    nonce,
		X:        x,
		Y:        y,
		Gates:    gates,
		LastPool: &SizedPool{Size: 32},
	}

	err = w.ApplyNonce()

	if err != nil {
		return nil, err
	}

	return w, nil
}

func (w *Waver) PassThroughGates(val byte) byte {
	for _, gate := range w.Gates {
		val = gate.PassValue(val, w.OffsetSum)
	}

	return val
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

func (w *Waver) XORCross(x, y uint8) {
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

func (w *Waver) GetNext() byte {
	currentVal := w.Matrix[w.X][w.Y]
	w.OffsetSum = uint8((int(w.OffsetSum) + int(currentVal)) % 256)

	dx := (w.OffsetSum % 13) + 1
	dy := (w.OffsetSum % 11) + 1

	deltaVal := w.Matrix[(w.X+dx)%16][(w.Y+dy)%16]

	w.LastPool.Add(currentVal)

	returning := ((currentVal << 3) | (currentVal >> 5)) +
		((deltaVal << 1) | (deltaVal >> 7)) +
		w.OffsetSum

	w.Matrix[w.X][w.Y] ^= w.OffsetSum

	stepDX := (w.OffsetSum ^ w.Matrix[(w.X+1)%16][w.Y]) % 16
	stepYX := (w.OffsetSum + w.Matrix[w.X][(w.Y+1)%16]) % 16

	w.XORCross(w.X, w.Y)

	w.X = (w.X + stepDX) % 16
	w.Y = (w.Y + stepYX) % 16

	r := w.PassThroughGates(returning)
	r = w.MixByte(r)

	return r
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
