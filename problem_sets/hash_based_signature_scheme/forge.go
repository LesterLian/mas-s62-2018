package main

import (
	"fmt"
)

/*
A note about the provided keys and signatures:
the provided pubkey and signature, as well as "HexTo___" functions may not work
with all the different implementations people could built.  Specifically, they
are tied to an endian-ness.  If, for example, you decided to encode your public
keys as (according to the diagram in the slides) up to down, then left to right:
<bit 0, row 0> <bit 0, row 1> <bit 1, row 0> <bit 1, row 1> ...

then it won't work with the public key provided here, because it was encoded as
<bit 0, row 0> <bit 1, row 0> <bit 2, row 0> ... <bit 255, row 0> <bit 0, row 1> ...
(left to right, then up to down)

so while in class I said that any decisions like this would work as long as they
were consistent... that's not actually the case!  Because your functions will
need to use the same ordering as the ones I wrote in order to create the signatures
here.  I used what I thought was the most straightforward / simplest encoding, but
endian-ness is something of a tabs-vs-spaces thing that people like to argue
about :).

So for clarity, and since it's not that obvious from the HexTo___ decoding
functions, here's the order used:

secret keys and public keys:
all 256 elements of row 0, most significant bit to least significant bit
(big endian) followed by all 256 elements of row 1.  Total of 512 blocks
of 32 bytes each, for 16384 bytes.
For an efficient check of a bit within a [32]byte array using this ordering,
you can use:
    arr[i/8]>>(7-(i%8)))&0x01
where arr[] is the byte array, and i is the bit number; i=0 is left-most, and
i=255 is right-most.  The above statement will return a 1 or a 0 depending on
what's at that bit location.

Messages: messages are encoded the same way the sha256 function outputs, so
nothing to choose there.

Signatures: Signatures are also read left to right, MSB to LSB, with 256 blocks
of 32 bytes each, for a total of 8192 bytes.  There is no indication of whether
the provided preimage is from the 0-row or the 1-row; the accompanying message
hash can be used instead, or both can be tried.  This again interprets the message
hash in big-endian format, where
    message[i/8]>>(7-(i%8)))&0x01
can be used to determine which preimage block to reveal, where message[] is the
message to be signed, and i is the sequence of bits in the message, and blocks
in the signature.

Hopefully people don't have trouble with different encoding schemes.  If you
really want to use your own method which you find easier to work with or more
intuitive, that's OK!  You will need to re-encode the key and signatures provided
in signatures.go to match your ordering so that they are valid signatures with
your system.  This is probably more work though and I recommend using the big
endian encoding described here.

*/

// Forge is the forgery function, to be filled in and completed.  This is a trickier
// part of the assignment which will require the computer to do a bit of work.
// It's possible for a single core or single thread to complete this in a reasonable
// amount of time, but may be worthwhile to write multithreaded code to take
// advantage of multi-core CPUs.  For programmers familiar with multithreaded code
// in golang, the time spent on parallelizing this code will be more than offset by
// the CPU time speedup.  For programmers with access to 2-core or below CPUs, or
// who are less familiar with multithreaded code, the time taken in programming may
// exceed the CPU time saved.  Still, it's all about learning.
// The Forge() function doesn't take any inputs; the inputs are all hard-coded into
// the function which is a little ugly but works OK in this assigment.
// The input public key and signatures are provided in the "signatures.go" file and
// the code to convert those into the appropriate data structures is filled in
// already.
// Your job is to have this function return two things: A string containing the
// substring "forge" as well as your name or email-address, and a valid signature
// on the hash of that ascii string message, from the pubkey provided in the
// signatures.go file.
// The Forge function is tested by TestForgery() in forge_test.go, so if you
// run "go test" and everything passes, you should be all set.
func Forge() (string, Signature, error) {
	// decode pubkey, all 4 signatures into usable structures from hex strings
	pub, err := HexToPubkey(hexPubkey1)
	if err != nil {
		panic(err)
	}

	sig1, err := HexToSignature(hexSignature1)
	if err != nil {
		panic(err)
	}
	sig2, err := HexToSignature(hexSignature2)
	if err != nil {
		panic(err)
	}
	sig3, err := HexToSignature(hexSignature3)
	if err != nil {
		panic(err)
	}
	sig4, err := HexToSignature(hexSignature4)
	if err != nil {
		panic(err)
	}

	var sigslice []Signature
	sigslice = append(sigslice, sig1)
	sigslice = append(sigslice, sig2)
	sigslice = append(sigslice, sig3)
	sigslice = append(sigslice, sig4)

	var msgslice []Message

	msgslice = append(msgslice, GetMessageFromString("1"))
	msgslice = append(msgslice, GetMessageFromString("2"))
	msgslice = append(msgslice, GetMessageFromString("3"))
	msgslice = append(msgslice, GetMessageFromString("4"))

	// Check which hash has been used
	zeroUsed := Message{}
	oneUsed := Message{}
	zeroUsedSigs := [256]Block{}
	oneUsedSigs := [256]Block{}
	for _, sig := range sigslice {
		for i, block := range sig.Preimage {
			hash := block.Hash()
			if pub.ZeroHash[i] == hash {
				zeroUsed[i/8] |= 0x01 << (7 - (i % 8))
				zeroUsedSigs[i] = block
			} else if pub.OneHash[i] == hash {
				oneUsed[i/8] |= 0x01 << (7 - (i % 8))
				oneUsedSigs[i] = block
			} else {
				panic("no match")
			}
		}
	}
	// Calculate forgary difficulty
	difficulty := 0
	for i := range zeroUsed {
		allTaken := zeroUsed[i] & oneUsed[i]
		for j := 0; j < 8; j++ {
			bit := allTaken >> (7 - j) & 1
			if bit == 0 {
				difficulty += 1
			}
		}
	}
	fmt.Printf("Zero taken: %x\n", zeroUsed)
	fmt.Printf("One taken: %x\n", oneUsed)
	fmt.Printf("Difficulty: %d\n", 1<<difficulty)

	// Recover message 1 from signature, because verification was failed
	// The cause was Sign and Verify functions were wrongly implemented.
	// pre1 := Signature{}
	// for i, block := range sig1.Preimage {
	// 	pre1.Preimage[i] = block.Hash()
	// }
	// msg1 := Message{}
	// for i, block := range pre1.Preimage {
	// 	if pub.ZeroHash[i] == block {
	// 		msg1[i/8] &= ^(0x01 << (7 - (i % 8)))
	// 	} else if pub.OneHash[i] == block {
	// 		msg1[i/8] |= 0x01 << (7 - (i % 8))
	// 	} else {
	// 		panic("no match")
	// 	}
	// }
	// fmt.Printf("msg1: %x\n", msgslice[0])
	// fmt.Printf("msg1 computed: %x\n", msg1)

	fmt.Printf("ok 1: %v\n", Verify(msgslice[0], pub, sig1))
	fmt.Printf("ok 2: %v\n", Verify(msgslice[1], pub, sig2))
	fmt.Printf("ok 3: %v\n", Verify(msgslice[2], pub, sig3))
	fmt.Printf("ok 4: %v\n", Verify(msgslice[3], pub, sig4))

	// Check if a message contains only bits used in previous signatures
	isForgeable := func(msgString string, output chan<- string) {
		forgeMsg := GetMessageFromString(msgString)
		forgeable := Message{}

		for i, block := range forgeMsg {
			forgeable[i] = block & oneUsed[i]
			forgeable[i] |= ^block & zeroUsed[i]
			if forgeable[i] != 0xff {
				// fmt.Printf("%d notforgeable: %x\n", i, block)
				output <- ""
				return
			}
		}

		output <- msgString
	}

	// Find forgeable message asynchronously
	var msgString string
	q := make(chan string, 8)
	go func(output chan<- string) {
		for i := 555735188; ; i++ {
			msgString = fmt.Sprintf("zlian forge %d", i)

			go isForgeable(msgString, output)
		}
	}(q)
	// Consume channel output and return a forgeable message
	for {
		result := <-q
		// Skip non-forgable messages
		if result == "" {
			continue
		}
		fmt.Printf("Found forgeable message: %s\n", result)
		// Find corresponding signature blocks
		message := GetMessageFromString(result)
		var forgeSig Signature
		for i := 0; i < 256; i++ {
			bit := message[i/8] >> (7 - i%8) & 0x01
			if bit == 0 {
				forgeSig.Preimage[i] = zeroUsedSigs[i]
			} else {
				forgeSig.Preimage[i] = oneUsedSigs[i]
			}
		}
		return result, forgeSig, nil
	}
}

// hint:
// arr[i/8]>>(7-(i%8)))&0x01
