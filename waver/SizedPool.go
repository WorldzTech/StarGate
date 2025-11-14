package waver

type SizedPool struct {
	Size int
	State []byte
	Sum uint8
}

func NewSizedPool(size int) *SizedPool {
	return &SizedPool{Size: size}
}

func (sp *SizedPool) Add(val uint8) {
	sp.Sum += val
	sp.State = append(sp.State, val)
	if len(sp.State) > sp.Size {
		sp.Sum -= sp.State[0]
		sp.State = sp.State[1:]
	}
}