package erc6492

import (
	"bytes"
	"fmt"

	"github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
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

// recoversToSigner reports whether signature is a plain 65-byte ECDSA signature
// of hash made by the private key of signer. Both v in {0, 1} and {27, 28} are accepted.
//
// EIP-7702 delegated EOAs have code, so the universal validator routes them to
// ERC-1271 on the delegate implementation, which may not implement it or may use
// a different hashing scheme. The EOA key keeps full control over a delegated
// account, so a valid ECDSA signature from it is authoritative.
func recoversToSigner(hash common.Hash, signature []byte, signer common.Address) bool {
	if len(signature) != crypto.SignatureLength {
		return false
	}

	sig := make([]byte, crypto.SignatureLength)
	copy(sig, signature)
	if sig[crypto.RecoveryIDOffset] >= 27 {
		sig[crypto.RecoveryIDOffset] -= 27
	}

	pub, err := crypto.SigToPub(hash.Bytes(), sig)
	if err != nil {
		return false
	}

	return crypto.PubkeyToAddress(*pub) == signer
}
