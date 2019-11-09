package main

import (
	"bytes"
	"encoding/hex"
	"errors"
	"fmt"
	"io/ioutil"
	"log"

	"golang.org/x/crypto/openpgp"
)

func main() {
	key := []byte("abc123")
	body := "c30d040903027b2f55c751bca96a68d23601a6aad41b60ba26b4eb9addd8f6337eba6b3efc0b54ff84881108cd84aafcafb3fd233eb4222fa2b3c33abeb75f2af2d6ee23fe134e"
	b, _ := hex.DecodeString(body)

	msg, err := decrypt(b, key)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Println(msg)
}

// decrypt will decrypt an encrypted column created from pgp_sym_encrypt():
// select pgp_sym_decrypt(pgp_sym_encrypt('hello', 'abc123', 'cipher-algo=aes256'), 'abc123');
func decrypt(b, key []byte) (string, error) {
	buf := bytes.NewBuffer(b)
	md, err := openpgp.ReadMessage(buf, nil, promptFunc(key), nil)
	if err != nil {
		return "", err
	}

	bytes, err := ioutil.ReadAll(md.UnverifiedBody)
	if err != nil {
		return "", err
	}

	return string(bytes), nil
}

// PromptFunc passes our symmetric key into openpgp for decryption.
// However, the openpgp.PromptFunction will run again if the
// passphrase is incorrect, so we have to stop it from endlessly checking a bad key.
func promptFunc(key []byte) openpgp.PromptFunction {
	var keyFailure bool
	return func([]openpgp.Key, bool) ([]byte, error) {
		if keyFailure {
			return nil, errors.New("Invalid PGP passphrase")
		} else {
			keyFailure = true
		}
		return key, nil
	}
}
