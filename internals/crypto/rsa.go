package crypto

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"
	"path/filepath"
)

// GenerateKeyPair generates an RSA key pair and saves them to the specified directory
func GenerateKeyPair(dir string) error {
	// Generate RSA key pair
	privateKey, err := rsa.GenerateKey(rand.Reader, 4096)
	if err != nil {
		return fmt.Errorf("error generating RSA key: %w", err)
	}

	// Save private key
	privateFile, err := os.Create(filepath.Join(dir, "private.pem"))
	if err != nil {
		return fmt.Errorf("error creating private key file: %w", err)
	}
	defer privateFile.Close()

	privateKeyBytes := x509.MarshalPKCS1PrivateKey(privateKey)
	err = pem.Encode(privateFile, &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: privateKeyBytes,
	})
	if err != nil {
		return fmt.Errorf("error encoding private key: %w", err)
	}

	// Save public key
	publicFile, err := os.Create(filepath.Join(dir, "public.pem"))
	if err != nil {
		return fmt.Errorf("error creating public key file: %w", err)
	}
	defer publicFile.Close()

	publicKeyBytes, err := x509.MarshalPKIXPublicKey(&privateKey.PublicKey)
	if err != nil {
		return fmt.Errorf("error marshaling public key: %w", err)
	}

	err = pem.Encode(publicFile, &pem.Block{
		Type:  "RSA PUBLIC KEY",
		Bytes: publicKeyBytes,
	})
	if err != nil {
		return fmt.Errorf("error encoding public key: %w", err)
	}

	return nil
}

// LoadPrivateKey loads the private key from file
func LoadPrivateKey(filePath string) (*rsa.PrivateKey, error) {
	data, err := os.ReadFile(filePath)
	if err != nil {
		return nil, fmt.Errorf("error reading private key file: %w", err)
	}

	block, _ := pem.Decode(data)
	if block == nil || block.Type != "RSA PRIVATE KEY" {
		return nil, fmt.Errorf("invalid private key file")
	}

	privateKey, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("error parsing private key: %w", err)
	}

	return privateKey, nil
}

// LoadPublicKey loads the public key from file
func LoadPublicKey(filePath string) (*rsa.PublicKey, error) {
	data, err := os.ReadFile(filePath)
	if err != nil {
		return nil, fmt.Errorf("error reading public key file: %w", err)
	}

	block, _ := pem.Decode(data)
	if block == nil || block.Type != "RSA PUBLIC KEY" {
		return nil, fmt.Errorf("invalid public key file")
	}

	pubInterface, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("error parsing public key: %w", err)
	}

	publicKey, ok := pubInterface.(*rsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("not an RSA public key")
	}

	return publicKey, nil
}

// EncryptRSA encrypts data with the public key
func EncryptRSA(publicKey *rsa.PublicKey, plaintext []byte) ([]byte, error) {
	ciphertext, err := rsa.EncryptOAEP(sha256.New(), rand.Reader, publicKey, plaintext, nil)
	if err != nil {
		return nil, fmt.Errorf("error encrypting with RSA: %w", err)
	}
	return ciphertext, nil
}

// DecryptRSA decrypts data with the private key
func DecryptRSA(privateKey *rsa.PrivateKey, ciphertext []byte) ([]byte, error) {
	plaintext, err := rsa.DecryptOAEP(sha256.New(), rand.Reader, privateKey, ciphertext, nil)
	if err != nil {
		return nil, fmt.Errorf("error decrypting with RSA: %w", err)
	}
	return plaintext, nil
}