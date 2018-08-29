package main

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"log"
	"time"
	//"github.com/davecgh/go-spew/spew"
	"strconv"
)

// Block structure
type Block struct {
	Index     int
	Timestamp string
	PubKey    string
	Data      string
	Hash      string
	PrevHash  string
}

// Blockchain is a slice of structure
var Blockchain []Block

func calculateHash(block Block) string {

	record := string(block.Index) + block.Timestamp + block.PubKey + string(block.Data) + block.PrevHash
	h := sha256.New()
	h.Write([]byte(record))
	hashed := h.Sum(nil)
	return hex.EncodeToString(hashed)
}

func generateBlock(oldBlock Block, data, pubKey string) (Block, error) {

	var newBlock Block

	t := time.Now()

	newBlock.Index = oldBlock.Index + 1
	newBlock.Timestamp = t.String()
	newBlock.Data = data
	newBlock.PubKey = pubKey
	newBlock.PrevHash = oldBlock.Hash
	newBlock.Hash = calculateHash(newBlock)

	return newBlock, nil
}

func addBlock(newBlock Block) bool {
	lastBlock := Blockchain[len(Blockchain)-1]
	if isBlockValid(newBlock, lastBlock) {
		newBlockchain := append(Blockchain, newBlock)
		replaceChain(newBlockchain)
		return true
	}
	log.Println("A New block №" + strconv.Itoa(newBlock.Index) + " is NOT valid \n")

	return false
}

//Consensus

func isBlockValid(newBlock, oldBlock Block) bool {
	if oldBlock.Index+1 > newBlock.Index {
		// send a last block
		return false
	}

	if oldBlock.Hash != newBlock.PrevHash {
		return false
	}

	if calculateHash(newBlock) != newBlock.Hash {
		return false
	}

	fmt.Printf("%+v", newBlock)
	return true
}
func replaceChain(newBlocks []Block) {
	if len(newBlocks) > len(Blockchain) {
		Blockchain = newBlocks

	}

}
