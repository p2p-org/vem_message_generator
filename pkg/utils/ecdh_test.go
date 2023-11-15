package utils_test

import (
	"bytes"
	"crypto/ecdh"
	"crypto/rand"
	"testing"
	"vem_message_generator/pkg/utils"

	"github.com/stretchr/testify/require"
)

func TestECDHOperations(t *testing.T) {
	alicePrivateKey, err := ecdh.P256().GenerateKey(rand.Reader)
	require.NoError(t, err)
	alicePublicKey, err := utils.MarshalECDHPublicKey(alicePrivateKey.PublicKey())
	require.NoError(t, err)
	bobPrivateKey, bobSharedPrivateKey, err := utils.ComputeECDHSharedSecret(alicePublicKey)
	require.NoError(t, err)
	aliceSharedPrivateKey, err := utils.ComputeECDHSharedSecretGeneric(alicePrivateKey, bobPrivateKey.PublicKey())
	require.NoError(t, err)
	ciphertext, err := utils.EncryptECIES(&bobSharedPrivateKey.PublicKey, []byte("test12345"))
	require.NoError(t, err)
	decryptedText, err := utils.DecryptECIES(bobSharedPrivateKey, ciphertext)
	require.NoError(t, err)
	ciphertext2, err := utils.EncryptECIES(&aliceSharedPrivateKey.PublicKey, []byte("test12345"))
	require.NoError(t, err)
	decryptedText2, err := utils.DecryptECIES(aliceSharedPrivateKey, ciphertext2)
	require.NoError(t, err)
	require.True(t, bytes.Equal(decryptedText, decryptedText2) && string(decryptedText2) == "test12345")
}

func TestConvertECDHtoECDSAPublicKey(t *testing.T) {
	// given
	ecdhClientKey, err := ecdh.P256().GenerateKey(rand.Reader)
	require.NoError(t, err)
	encodedKey, err := utils.MarshalECDHPublicKey(ecdhClientKey.PublicKey())
	require.NoError(t, err)

	// when
	decodedECDSPubKey, err := utils.ConvertECDHtoECDSAPublicKey(encodedKey)
	require.NoError(t, err)

	// then
	ecdhFromDecodedToECDS, err := decodedECDSPubKey.ECDH()
	require.NoError(t, err)
	require.True(t, ecdhFromDecodedToECDS.Equal(ecdhClientKey.PublicKey()))
}

func TestConvertECDHtoECDSAPrivateKey(t *testing.T) {
	// given
	ecdhClientKey, err := ecdh.P256().GenerateKey(rand.Reader)
	require.NoError(t, err)

	// when
	convertedECDSAPrivateKey, err := utils.ConvertECDHtoECDSAPrivateKey(ecdhClientKey)
	require.NoError(t, err)

	// then
	ecdhFromDecodedToECDS, err := convertedECDSAPrivateKey.ECDH()
	require.NoError(t, err)
	require.True(t, ecdhFromDecodedToECDS.Equal(ecdhClientKey))
}
