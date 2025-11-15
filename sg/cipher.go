package sg

import (
	"os"

	"github.com/schollz/progressbar/v3"
)

type Cipher struct {
	waver *Waver
}

func NewCipher(key, nonce string) (*Cipher, error) {
	waver, err := NewWaver(key, nonce)

	if err != nil {
		return nil, err
	}

	return &Cipher{
		waver: waver,
	}, nil
}

func (c *Cipher) WorkWithFile(filepath, newFilePath string) error {
	b, err := os.ReadFile(filepath)

	if err != nil {
		return err
	}

	workedBytes := make([]byte, len(b))

	bar := progressbar.Default(int64(len(b)))

	for i := 0; i < len(b); i++ {
		workedBytes[i] = b[i] ^ c.waver.GetNext()
		bar.Add(1)
	}

	file, _ := os.Create(newFilePath)
	_, err = file.Write(workedBytes)
	if err != nil {
		return err
	}

	file.Close()

	return nil
}

func (c *Cipher) WorkWithMessage(message string) string {
	cipherText := ""

	for _, char := range message {
		cipherText += string(char ^ rune(c.waver.GetNext()))
	}

	return cipherText
}

func (c *Cipher) GetNextByte() byte {
	return c.waver.GetNext()
}
