package main

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
)

// --Helper Functions defined for test and forge
// GetMessageFromString returns a Message which is the hash of the given string.
func GetMessageFromString(s string) Message {
	return sha256.Sum256([]byte(s))
}

// BlockFromByteSlice returns a block from a variable length byte slice.
// Watch out!  Silently ignores potential errors like the slice being too
// long or too short!
func BlockFromByteSlice(by []byte) Block {
	var bl Block
	copy(bl[:], by)
	return bl
}

// HexToPubkey takes a string from PublicKey.ToHex() and turns it into a pubkey
// will return an error if there are non hex characters or if the lenght is wrong.
func HexToPubkey(s string) (PublicKey, error) {
	var p PublicKey

	expectedLength := 256 * 2 * 64 // 256 blocks long, 2 rows, 64 hex char per block

	// first, make sure hex string is of correct length
	if len(s) != expectedLength {
		return p, fmt.Errorf(
			"Pubkey string %d characters, expect %d", len(s), expectedLength)
	}

	// decode from hex to a byte slice
	bts, err := hex.DecodeString(s)
	if err != nil {
		return p, err
	}
	// we already checked the length of the hex string so don't need to re-check
	buf := bytes.NewBuffer(bts)

	for i := range p.ZeroHash {
		p.ZeroHash[i] = BlockFromByteSlice(buf.Next(32))
	}
	for i := range p.OneHash {
		p.OneHash[i] = BlockFromByteSlice(buf.Next(32))
	}

	return p, nil
}

// HexToSignature is the same idea as HexToPubkey, but half as big.  Format is just
// every block of the signature in sequence.
func HexToSignature(s string) (Signature, error) {
	var sig Signature

	expectedLength := 256 * 64 // 256 blocks long, 1 row, 64 hex char per block

	// first, make sure hex string is of correct length
	if len(s) != expectedLength {
		return sig, fmt.Errorf(
			"Pubkey string %d characters, expect %d", len(s), expectedLength)
	}

	// decode from hex to a byte slice
	bts, err := hex.DecodeString(s)
	if err != nil {
		return sig, err
	}
	// we already checked the length of the hex string so don't need to re-check
	buf := bytes.NewBuffer(bts)

	for i := range sig.Preimage {
		sig.Preimage[i] = BlockFromByteSlice(buf.Next(32))
	}
	return sig, nil
}

const MESSAGE_BITS = 256
const MESSAGE_BYTES = MESSAGE_BITS / 8

type Block [MESSAGE_BYTES]byte

// Hash returns the sha256 hash of the block.
func (self Block) Hash() Block {
	return sha256.Sum256(self[:])
}

type Message [MESSAGE_BYTES]byte // 256 bits
type PublicKey struct {
	ZeroHash [MESSAGE_BITS]Block
	OneHash  [MESSAGE_BITS]Block
}
type PrivateKey struct {
	ZeroHash [MESSAGE_BITS]Block
	OneHash  [MESSAGE_BITS]Block
}

func (self PrivateKey) GetPublicKey() PublicKey {
	pub := PublicKey{ZeroHash: [MESSAGE_BITS]Block{}, OneHash: [MESSAGE_BITS]Block{}}

	for i, block := range self.ZeroHash {
		pub.ZeroHash[i] = block.Hash()
	}
	for i, block := range self.OneHash {
		pub.OneHash[i] = block.Hash()
	}
	return pub
}

type Signature struct {
	Preimage [MESSAGE_BITS]Block
}

func main() {
	msg := GetMessageFromString("test")
	pri, pub, err := GenerateKey()
	if err != nil {
		fmt.Printf("Error generating key: %v", err)
		return
	}
	signature := Sign(msg, pri)
	result := Verify(msg, pub, signature)
	fmt.Printf("Verify worked? %v", result)

	forgeString, forgeSig, _ := Forge()

	fmt.Printf("Forged message: %s\n%x", forgeString, forgeSig.Preimage)
}

func ReadHash() ([MESSAGE_BITS]Block, error) {
	hash := [MESSAGE_BITS]Block{}
	for i := 0; i < MESSAGE_BITS; i++ {
		block := make([]byte, MESSAGE_BYTES)
		_, err := rand.Read(block)
		if err != nil {
			fmt.Println("error:", err)
			return [MESSAGE_BITS]Block{}, err
		}

		hash[i] = BlockFromByteSlice(block)
	}

	return hash, nil
}

// GenerateKey takes no arguments, and returns a keypair and potentially an
// error.  It gets randomness from the OS via crypto/rand
// This can return an error if there is a problem with reading random bytes
func GenerateKey() (PrivateKey, PublicKey, error) {
	pri := PrivateKey{ZeroHash: [MESSAGE_BITS]Block{}, OneHash: [MESSAGE_BITS]Block{}}

	var err error
	pri.ZeroHash, err = ReadHash()
	if err != nil {
		return PrivateKey{}, PublicKey{}, err
	}
	pri.OneHash, err = ReadHash()
	if err != nil {
		return PrivateKey{}, PublicKey{}, err
	}
	pub := pri.GetPublicKey()

	return pri, pub, nil
}

// Sign takes a message and secret key, and returns a signature.
func Sign(msg Message, pri PrivateKey) Signature {
	sig := Signature{}

	for i, b := range msg {
		for j := 0; j < 8; j++ {
			bit := b >> (7 - j) & 1
			if bit == 0 {
				sig.Preimage[i*8+j] = pri.ZeroHash[i*8+j]
			} else {
				sig.Preimage[i*8+j] = pri.OneHash[i*8+j]
			}
		}
	}

	return sig
}

// Verify takes a message, public key and signature, and returns a boolean
// describing the validity of the signature.
func Verify(msg Message, pub PublicKey, sig Signature) bool {
	for i, b := range msg {
		for j := 0; j < 8; j++ {
			bit := b >> (7 - j) & 1
			if bit == 0 {
				if sig.Preimage[i*8+j].Hash() != pub.ZeroHash[i*8+j] {
					return false
				}
			} else {
				if sig.Preimage[i*8+j].Hash() != pub.OneHash[i*8+j] {
					return false
				}
			}
		}
	}

	return true
}
