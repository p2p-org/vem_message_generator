package service

import (
	"crypto/ecdh"
	"encoding/base64"
	"encoding/hex"
	"github.com/ethereum/go-ethereum/crypto/ecies"
	"log"
	"vem_message_generator/pkg/utils"
)

func (s *Generator) DecryptData(ecdhPrivateKey, encryptedMessage *string) {
	if !utils.ValidateString(ecdhPrivateKey) || !utils.ValidateString(encryptedMessage) {
		log.Fatal("invalid params. you must specify ecdhPrivateKey and encryptedMessage")
	}

	privateBytes, err := hex.DecodeString(*ecdhPrivateKey)
	if err != nil {
		log.Fatal("failed to decode private key: ", err)
	}
	curve := ecdh.P256()
	ecdhClientKey, err := curve.NewPrivateKey(privateBytes)
	if err != nil {
		log.Fatal("failed to create private key: ", err)
	}
	ecdsaClientKey, err := utils.ConvertECDHtoECDSAPrivateKey(ecdhClientKey)
	if err != nil {
		log.Fatal("failed to convert ecdh to ecdsa private key: ", err)
	}

	ciphertext, err := base64.StdEncoding.DecodeString(*encryptedMessage)
	if err != nil {
		log.Fatal("failed to decode base64: ", err)
	}
	decryptedVemPayload, err := ecies.ImportECDSA(ecdsaClientKey).Decrypt(ciphertext, nil, nil)
	if err != nil {
		log.Fatal("failed to decrypt vem payload: ", err)
	}
	log.Println("decrypted vem payload: ", string(decryptedVemPayload))
}
