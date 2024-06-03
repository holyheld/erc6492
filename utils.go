package erc6492

import (
	"bytes"
	"fmt"

	"github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/ethereum/go-ethereum/common"
)

var addressType, _ = abi.NewType("address", "", []abi.ArgumentMarshaling{
	{Type: "address", Name: "_signer"},
})

var bytes32Type, _ = abi.NewType("bytes32", "", []abi.ArgumentMarshaling{
	{Type: "bytes32", Name: "_hash"},
})

var bytesType, _ = abi.NewType("bytes", "", []abi.ArgumentMarshaling{
	{Type: "bytes", Name: "_signature"},
})

func encodeData(signer common.Address, hash [32]byte, signature []byte) ([]byte, error) {
	args := abi.Arguments{
		{Type: addressType, Name: "_signer"},
		{Type: bytes32Type, Name: "_hash"},
		{Type: bytesType, Name: "_signature"},
	}

	packed, err := args.Pack(signer, hash, signature)
	if err != nil {
		return nil, fmt.Errorf("failed to pack data: %w", err)
	}

	buf := bytes.Buffer{}
	buf.Grow(len(universalValidator) + len(packed))
	buf.Write(universalValidator)
	buf.Write(packed)

	return buf.Bytes(), nil
}
