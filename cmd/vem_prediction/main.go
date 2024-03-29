package main

import (
	"flag"
	"vem_message_generator/pkg/service"
	"vem_message_generator/pkg/utils"
)

var (
	ecdhPrivateKey   = flag.String("ecdhPrivateKey", "", "ecdh private key")
	encryptedMessage = flag.String("encryptedMessage", "", "encrypted message")
	validatorsList   = flag.String("validators", "", "comma-separated list of validators")
	predictedIndex   = flag.String("predictedIndex", "", "comma-separated list of indexes")
	pk               = flag.String("pk", "", "private key")
)

func main() {
	flag.Parse()
	srv := service.NewGenerator()
	if utils.ValidateString(pk) {
		srv.PrepareVEMPredictionRequest(*pk, *validatorsList, *predictedIndex)
	} else {
		srv.DecryptData(ecdhPrivateKey, encryptedMessage)
	}
}
