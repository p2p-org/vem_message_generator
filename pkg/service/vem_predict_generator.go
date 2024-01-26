package service

import (
	"crypto/ecdh"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"strconv"
	"strings"
	"vem_message_generator/pkg/entities"
	"vem_message_generator/pkg/utils"

	"github.com/ethereum/go-ethereum/crypto"
	"github.com/google/uuid"
)

func (s *Generator) PrepareVEMPredictionRequest(privateKey, validatorsList, predictedIndex string) {
	validatorsPubKeys := strings.Split(validatorsList, ",")
	if len(validatorsPubKeys) == 0 {
		log.Fatal("no validators provided")
	}
	predictedIndexesStr := strings.Split(predictedIndex, ",")
	if len(predictedIndexesStr) == 0 {
		log.Fatal("no predicted indexes provided")
	}
	predictedIndexes := make([]uint64, len(predictedIndexesStr))
	for i := range predictedIndexesStr {
		index, err := strconv.Atoi(predictedIndexesStr[i])
		if err != nil {
			log.Fatal("failed to parse predicted index: ", err)
		}
		predictedIndexes[i] = uint64(index)
	}
	log.Println(fmt.Sprintf("generate vem prediction for validators: %s, for indexes: %s", validatorsPubKeys, predictedIndex))

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
	generatedVemPredictionRequest, err := json.Marshal(entities.VEMPredictRequest{
		ValidatorsPubKeys:         validatorsPubKeys,
		PredictedIndexes:          predictedIndexes,
		ClientECDHPublicKeyBase64: encodedKey,
	})
	if err != nil {
		log.Fatal("failed to marshal sample data: ", err)
	}
	signature := sign(privateKeyECDSA, string(generatedVemPredictionRequest))
	signedBy := checkSign(signature, string(generatedVemPredictionRequest))
	clientAddress, err := utils.KeyToAddress(privateKeyECDSA)
	if signedBy != clientAddress.String() {
		log.Fatal("signatures mismatch")
	}

	signedContainer, err := json.Marshal(entities.VEMRequestContainer{
		VemRequestID:        uuid.New(),
		VemRequest:          string(generatedVemPredictionRequest),
		VemRequestSignature: signature,
		VemRequestSignedBy:  clientAddress.String(),
	})

	log.Println("vem prediction request signature: ", string(signedContainer))
	log.Println("secret key:", hex.EncodeToString(ecdhClientKey.Bytes()))
	log.Println("secret public key:", encodedKey)
}
