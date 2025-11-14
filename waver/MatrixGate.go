package waver

type MatrixGate struct {
	Matrix [][]byte
}

func NewMatrixGate(vals []byte) *MatrixGate {
	var matrix [][]byte

	for i := range 4 {
		matrix = append(matrix, vals[i*4:(i+1)*4])
	}

	return &MatrixGate{
		Matrix: matrix,
	}
}

func (gate *MatrixGate) PassValue(val byte, accum byte) uint8 {
	x := accum % 4
	y := (accum / 4) % 4

	v := gate.Matrix[x][y]

	gate.Matrix[x][y] = uint8(int(v + val) % 256)

	return uint8(int(val + v) % 256)
}