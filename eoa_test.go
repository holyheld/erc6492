package erc6492

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"errors"
	"math/big"
	"testing"

	"github.com/ethereum/go-ethereum"
	"github.com/ethereum/go-ethereum/accounts"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
)

// fakeCaller simulates the universal validator call, e.g. a reverting
// ERC-1271 call on an EIP-7702 delegate that doesn't implement it.
type fakeCaller struct {
	res   []byte
	err   error
	calls int
}

func (f *fakeCaller) CodeAt(context.Context, common.Address, *big.Int) ([]byte, error) {
	return nil, nil
}

func (f *fakeCaller) CallContract(context.Context, ethereum.CallMsg, *big.Int) ([]byte, error) {
	f.calls++
	return f.res, f.err
}

func TestValidator_ValidateEOASignature(t *testing.T) {
	key, err := crypto.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	otherKey, err := crypto.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	signer := crypto.PubkeyToAddress(key.PublicKey).Hex()
	message := []byte("hello 7702")

	sign := func(t *testing.T, k *ecdsa.PrivateKey, vOffset byte) string {
		t.Helper()
		sig, err := crypto.Sign(accounts.TextHash(message), k)
		if err != nil {
			t.Fatal(err)
		}
		sig[crypto.RecoveryIDOffset] += vOffset
		return common.Bytes2Hex(sig)
	}

	errReverted := errors.New("execution reverted")

	tests := []struct {
		name      string
		signature string
		caller    *fakeCaller
		want      bool
		wantErr   bool
		wantCalls int
	}{
		{
			name:      "v 27/28, contract call reverts",
			signature: sign(t, key, 27),
			caller:    &fakeCaller{err: errReverted},
			want:      true,
		},
		{
			name:      "v 0/1, contract call reverts",
			signature: sign(t, key, 0),
			caller:    &fakeCaller{err: errReverted},
			want:      true,
		},
		{
			name:      "v 27/28, contract returns invalid",
			signature: "0x" + sign(t, key, 27),
			caller:    &fakeCaller{res: resultInvalid},
			want:      true,
		},
		{
			name:      "other key falls back to contract",
			signature: sign(t, otherKey, 27),
			caller:    &fakeCaller{res: resultInvalid},
			want:      false,
			wantCalls: 1,
		},
		{
			name:      "other key, contract call reverts",
			signature: sign(t, otherKey, 27),
			caller:    &fakeCaller{err: errReverted},
			wantErr:   true,
			wantCalls: 1,
		},
		{
			name:      "non-ECDSA signature falls back to contract",
			signature: "0xdeadbeef",
			caller:    &fakeCaller{res: resultValid},
			want:      true,
			wantCalls: 1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := NewValidator(tt.caller).Validate(context.Background(), message, signer, tt.signature)
			if (err != nil) != tt.wantErr {
				t.Fatalf("Validate() error = %v, wantErr %v", err, tt.wantErr)
			}
			if got != tt.want {
				t.Errorf("Validate() = %v, want %v", got, tt.want)
			}
			if tt.caller.calls != tt.wantCalls {
				t.Errorf("contract calls = %d, want %d", tt.caller.calls, tt.wantCalls)
			}
		})
	}
}

func TestRecoversToSigner(t *testing.T) {
	key, err := crypto.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	signer := crypto.PubkeyToAddress(key.PublicKey)
	hash := common.BytesToHash(accounts.TextHash([]byte("hello 7702")))

	sig, err := crypto.Sign(hash.Bytes(), key)
	if err != nil {
		t.Fatal(err)
	}

	withV := func(v byte) []byte {
		s := common.CopyBytes(sig)
		s[crypto.RecoveryIDOffset] = v
		return s
	}

	tests := []struct {
		name      string
		signature []byte
		signer    common.Address
		want      bool
	}{
		{name: "v 0/1", signature: sig, signer: signer, want: true},
		{name: "v 27/28", signature: withV(sig[crypto.RecoveryIDOffset] + 27), signer: signer, want: true},
		{name: "invalid v 2", signature: withV(2), signer: signer},
		{name: "invalid v 255", signature: withV(255), signer: signer},
		{name: "64 bytes", signature: sig[:64], signer: signer},
		{name: "66 bytes", signature: append(common.CopyBytes(sig), 0), signer: signer},
		{name: "empty", signature: nil, signer: signer},
		{name: "wrong signer", signature: sig, signer: common.HexToAddress("0x45FB5699C0BFFC5e7D7F0c4947417833cc0623aa")},
		{name: "zero signer", signature: sig, signer: common.Address{}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			before := common.CopyBytes(tt.signature)
			if got := recoversToSigner(hash, tt.signature, tt.signer); got != tt.want {
				t.Errorf("recoversToSigner() = %v, want %v", got, tt.want)
			}
			if !bytes.Equal(before, tt.signature) {
				t.Errorf("signature was mutated: %x -> %x", before, tt.signature)
			}
		})
	}
}
