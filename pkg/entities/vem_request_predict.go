package entities

import (
	"github.com/attestantio/go-eth2-client/spec/phase0"
	"github.com/google/uuid"
)

type VEMPredictRequest struct {
	// ValidatorsPubKeys of validators for whom we want to generate predicted VEMs
	ValidatorsPubKeys []string `json:"validators_pub_keys"`
	// PredictedIndexes are indexes of validators for whom we want to generate predicted VEMs
	PredictedIndexes []uint64 `json:"predicted_indexes"`
	// ClientECDHPublicKeyBase64 is base64 encoded ECDH public key of client. we will generate shared secret and encrypt VEMs with it
	ClientECDHPublicKeyBase64 string `json:"ecdh_client_pubkey"`
}

type VEMPredictRequestContainer struct {
	VEMRequestID uuid.UUID `json:"vem_request_uid"`

	VEMPredictRequest          string `json:"vem_predict_request,omitempty"` // expect json of VEMPredictRequest
	VEMPredictRequestSignature string `json:"vem_predict_request_signature,omitempty"`
	VEMPredictRequestSignedBy  string `json:"vem_predict_request_signed_by,omitempty"`

	// Rabbit routing keys where answer should be sent
	ResultRoutingKey string `json:"resultRoutingKey,omitempty"`
	ErrRoutingKey    string `json:"errorRoutingKey,omitempty"`
}

func (v *VEMPredictRequestContainer) ErrorRoutingKey() string {
	return ""
}

type VEMPredictResult struct {
	PredictedVems map[string]map[uint64]*phase0.SignedVoluntaryExit `json:"requested_vems"`
}

type VEMPredictResultContainer struct {
	Result       RequestVEMStatus `json:"result"`
	VEMRequestID uuid.UUID        `json:"vem_request_uid"`

	VEMResult   string `json:"vem_result"` // expect json of VEMPredictResult
	Error       string `json:"error,omitempty"`
	ForkVersion string `json:"fork_version"`
}
