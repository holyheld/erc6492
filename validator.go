package erc6492

import (
	"bytes"
	"context"
	"fmt"
	"github.com/ethereum/go-ethereum"
	"github.com/ethereum/go-ethereum/accounts"
	"github.com/ethereum/go-ethereum/accounts/abi/bind"
	"github.com/ethereum/go-ethereum/common"
)

type Validator struct {
	client bind.ContractCaller
}

func NewValidator(client bind.ContractCaller) *Validator {
	return &Validator{
		client: client,
	}
}

func (v Validator) Validate(ctx context.Context, message []byte, signer string, signature string) (bool, error) {
	validatorAddress := common.HexToAddress(signer)

	hash := common.BytesToHash(accounts.TextHash(message))
	signatureHex := common.FromHex(signature)

	input, err := encodeData(validatorAddress, hash, signatureHex)
	if err != nil {
		return false, fmt.Errorf("failed to encode data to call predeploy contract: %w", err)
	}

	res, err := v.client.CallContract(ctx, ethereum.CallMsg{
		Data: input,
	}, nil)
	if err != nil {
		return false, fmt.Errorf("contract call failed: %w", err)
	}

	if bytes.Equal(res, resultValid) {
		return true, nil
	}

	if bytes.Equal(res, resultInvalid) {
		return false, nil
	}

	return false, fmt.Errorf("failed to validate: unexpected result from a validatator: %s", common.Bytes2Hex(res))
}
