package service

import (
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"log"
	"strings"
	"vem_message_generator/pkg/entities"
	"vem_message_generator/pkg/utils"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/google/uuid"
)

func (s *Generator) GenerateVEMRequest(privateKey, validatorsList string) {
	validatorsPubKeys := strings.Split(validatorsList, ",")
	if len(validatorsPubKeys) == 0 {
		log.Fatal("no validators provided")
	}
	log.Println("generate vem for validators: ", validatorsPubKeys)

	privateKeyECDSA, err := crypto.HexToECDSA(strings.ReplaceAll(privateKey, "0x", ""))
	if err != nil {
		log.Fatal("failed to cast key: ", err)
	}

	ecdhClientKey, err := ecdh.P256().GenerateKey(rand.Reader)
	if err != nil {
		log.Fatal("failed generate ecdh key: ", err)
	}
	encodedKey, err := utils.MarshalECDHPublicKey(ecdhClientKey.PublicKey())
	if err != nil {
		log.Fatal("failed to marshal ecdh public key: ", err)
	}
	generatedVemRequest, err := json.Marshal(entities.VEMRequest{
		Action:                    entities.RequestActionInitial,
		ValidatorsPubKeys:         validatorsPubKeys,
		ClientECDHPublicKeyBase64: encodedKey,
	})
	if err != nil {
		log.Fatal("failed to marshal sample data: ", err)
	}
	log.Println("======= VEM REQUEST =======")
	log.Println("vem request: ", string(generatedVemRequest))

	log.Println("======= VEM REQUEST SIGNATURE =======")
	clientAddress, err := utils.KeyToAddress(privateKeyECDSA)
	if err != nil {
		log.Fatal("failed to get client address: ", err)
	}

	signature := sign(privateKeyECDSA, string(generatedVemRequest))
	signedContainer, err := json.Marshal(entities.VEMRequestContainer{
		VemRequestID:        uuid.New(),
		VemRequest:          string(generatedVemRequest),
		VemRequestSignature: signature,
		VemRequestSignedBy:  clientAddress.String(),
	})
	if err != nil {
		log.Fatal("failed to marshal signed container: ", err)
	}
	signedBy := checkSign(signature, string(generatedVemRequest))
	if signedBy != clientAddress.String() {
		log.Fatal("signatures mismatch")
	}
	log.Println("======= VEM REQUEST SIGNATURE =======")
	log.Println("vem request signature: ", string(signedContainer))
	log.Println("secret key:", hex.EncodeToString(ecdhClientKey.Bytes()))
	log.Println("secret public key:", encodedKey)
}

func sign(privateKeyECDSA *ecdsa.PrivateKey, payload string) string {
	hash := crypto.Keccak256Hash([]byte(payload))
	signedData, err := crypto.Sign(hash.Bytes(), privateKeyECDSA)
	if err != nil {
		log.Fatal("failed to sign data: ", err)
	}
	return hexutil.Encode(signedData)
}

func checkSign(signature, payload string) string {
	hash := crypto.Keccak256Hash([]byte(payload))
	pkSign, err := crypto.SigToPub(hash[:], common.FromHex(signature))
	if err != nil {
		log.Fatal("failed to recover public key from signature: ", err)
	}
	return crypto.PubkeyToAddress(*pkSign).String()
}
