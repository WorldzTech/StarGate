package sg

import (
	"errors"
	"os"

	"github.com/schollz/progressbar/v3"
)

type Cipher struct {
	key   string
	Nonce string
	waver *Waver
}

func NewCipher(key, nonce string) (*Cipher, error) {
	waver, err := NewWaver(key, nonce)

	if err != nil {
		return nil, err
	}

	return &Cipher{
		key:   key,
		waver: waver,
		Nonce: waver.Nonce,
	}, nil
}

func (c *Cipher) ReinitializeWithNewNonce(nonce string) error {
	waver, err := NewWaver(c.key, nonce)

	if err != nil {
		return err
	}

	c.waver = waver
	return nil
}

func (c *Cipher) EncryptFile(filepath, newFilePath string) error {
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
	_, err = file.Write(append([]byte(c.waver.Nonce), workedBytes...))
	if err != nil {
		return err
	}

	file.Close()

	return nil
}

func (c *Cipher) DecryptFile(filepath, newFilePath string) error {
	b, err := os.ReadFile(filepath)

	if err != nil {
		return err
	}

	nonceB := b[:16]
	nonce := string(nonceB)

	err = c.ReinitializeWithNewNonce(nonce)
	if err != nil {
		return errors.New("failed to reinitialize cipher with new nonce: " + err.Error())
	}

	b = b[16:]

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
