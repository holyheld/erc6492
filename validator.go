package erc6492

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"github.com/ethereum/go-ethereum"
	"github.com/ethereum/go-ethereum/accounts"
	"github.com/ethereum/go-ethereum/accounts/abi/bind"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/rpc"
	"strings"
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
	return v.validate(ctx, message, signer, signature, false)
}

func (v Validator) validate(ctx context.Context, message []byte, signer string, signature string, retried bool) (bool, error) {
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
		var ree rpc.Error
		var rde rpc.DataError

		// as execution reverted error
		if errors.As(err, &ree) && errors.As(err, &rde) && ree.ErrorCode() == 3 {
			// an error caused by invalid v-component and raised by contract's require call
			if !retried && strings.HasSuffix(rde.Error(), "SignatureValidator#recoverSigner: invalid signature v value") && (signatureHex[64] == 0 || signatureHex[64] == 1) {
				// fix v-component of ecdsa signature
				signatureHexFixed := make([]byte, len(signatureHex), len(signatureHex))
				copy(signatureHexFixed, signatureHex)
				signatureHexFixed[64] += 27

				return v.validate(ctx, message, signer, common.Bytes2Hex(signatureHexFixed), true)
			}
		}

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
