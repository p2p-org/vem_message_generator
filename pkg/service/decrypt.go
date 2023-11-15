package service

import (
	"crypto/ecdh"
	"encoding/hex"
	"log"
	"vem_message_generator/pkg/utils"
)

func (s *Generator) DecryptData(ecdhPublicKey, ecdhPrivateKey, encryptedMessage *string) {
	if !utils.ValidateString(ecdhPublicKey) || !utils.ValidateString(ecdhPrivateKey) || !utils.ValidateString(encryptedMessage) {
		log.Fatal("invalid params. you must specify ecdhPublicKey, ecdhPrivateKey and encryptedMessage")
	}
	mvPK, err := utils.UnmarshalECDHPublicKey(*ecdhPublicKey)
	if err != nil {
		log.Fatal("failed to unmarshal ecdh public key: ", err)
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
	commonPrivateKey, err := utils.ComputeECDHSharedSecretGeneric(ecdhClientKey, mvPK)
	if err != nil {
		log.Fatal("failed to compute ecdh shared secret: ", err)
	}
	println("encryptedMessage: ", *encryptedMessage)
	decryptedVemPayload, err := utils.DecryptECIES(commonPrivateKey, *encryptedMessage)
	if err != nil {
		log.Fatal("failed to decrypt vem payload: ", err)
	}
	log.Println("decrypted vem payload: ", string(decryptedVemPayload))
}
