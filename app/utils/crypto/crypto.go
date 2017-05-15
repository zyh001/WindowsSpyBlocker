package crypto

import (
	"crypto/sha256"
	"encoding/hex"
	"io"
	"os"
)

func HashFileSha256(filePath string) (string, error) {
	var result string

	// Open the passed argument and check for any error
	file, err := os.Open(filePath)
	if err != nil {
		return result, err
	}

	// Tell the program to call the following function when the current function returns
	defer file.Close()

	// Open a new hash interface to write to
	hash := sha256.New()

	// Copy the file in the hash interface and check for any error
	if _, err := io.Copy(hash, file); err != nil {
		return result, err
	}

	//Get the 16 bytes hash
	hashInBytes := hash.Sum(nil)[:16]

	return hex.EncodeToString(hashInBytes), nil
}
