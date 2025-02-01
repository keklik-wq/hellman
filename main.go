package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"math/big"
)

func generateRandomBigInt(max *big.Int) (*big.Int, error) {
	return rand.Int(rand.Reader, max)
}

func computePublicKey(g, a, p *big.Int) *big.Int {
	return new(big.Int).Exp(g, a, p)
}

func computeSharedSecret(publicKey, privateKey, p *big.Int) *big.Int {
	return new(big.Int).Exp(publicKey, privateKey, p)
}

func encryptMessage(key []byte, message string) (string, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}

	ciphertext := make([]byte, aes.BlockSize+len(message))
	iv := ciphertext[:aes.BlockSize]
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		return "", err
	}

	stream := cipher.NewCFBEncrypter(block, iv)
	stream.XORKeyStream(ciphertext[aes.BlockSize:], []byte(message))

	return hex.EncodeToString(ciphertext), nil
}

func decryptMessage(key []byte, encryptedMessage string) (string, error) {
	ciphertext, err := hex.DecodeString(encryptedMessage)
	if err != nil {
		return "", err
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}

	if len(ciphertext) < aes.BlockSize {
		return "", fmt.Errorf("ciphertext too short")
	}

	iv := ciphertext[:aes.BlockSize]
	ciphertext = ciphertext[aes.BlockSize:]

	stream := cipher.NewCFBDecrypter(block, iv)
	stream.XORKeyStream(ciphertext, ciphertext)

	return string(ciphertext), nil
}

func main() {
	p := new(big.Int)                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                   // Большое простое число
	p.SetString("FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3BE39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF6955817183995497CEA956AE515D2261898FA051015728E5A8AACAA68FFFFFFFFFFFFFFFF", 16) // Пример большого простого числа

	g := big.NewInt(2)

	aPrivate, err := generateRandomBigInt(p)
	if err != nil {
		fmt.Println("Ошибка генерации приватного ключа Алисы:", err)
		return
	}

	bPrivate, err := generateRandomBigInt(p)
	if err != nil {
		fmt.Println("Ошибка генерации приватного ключа Боба:", err)
		return
	}

	aPublic := computePublicKey(g, aPrivate, p)
	bPublic := computePublicKey(g, bPrivate, p)

	aSharedSecret := computeSharedSecret(bPublic, aPrivate, p)
	bSharedSecret := computeSharedSecret(aPublic, bPrivate, p)

	if aSharedSecret.Cmp(bSharedSecret) == 0 {
		fmt.Println("Общий секретный ключ успешно вычислен!")
		fmt.Printf("Секретный ключ Алисы: %x\n", aSharedSecret)
		fmt.Printf("Секретный ключ Боба: %x\n", bSharedSecret)
	} else {
		fmt.Println("Ошибка: секретные ключи не совпадают!")
		return
	}

	sharedSecretBytes := aSharedSecret.Bytes()
	hash := sha256.Sum256(sharedSecretBytes)
	key := hash[:]

	message := "Привет, Боб! Это секретное сообщение."

	encryptedMessage, err := encryptMessage(key, message)
	if err != nil {
		fmt.Println("Ошибка шифрования:", err)
		return
	}
	fmt.Printf("Зашифрованное сообщение: %s\n", encryptedMessage)

	// Боб расшифровывает сообщение
	decryptedMessage, err := decryptMessage(key, encryptedMessage)
	if err != nil {
		fmt.Println("Ошибка расшифровки:", err)
		return
	}
	fmt.Printf("Расшифрованное сообщение: %s\n", decryptedMessage)
}
