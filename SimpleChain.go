package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"time"
	//"github.com/davecgh/go-spew/spew"
	"strconv"

	"github.com/gorilla/mux"
)

// Scan input

/* type syncNode interface {

	reqLastBlockNumber () error
	sendLastBlockNumber () error
	reqBlock (int) error
	sendBlock (int) error



} */
func genRsaKeyPair() (*rsa.PrivateKey, *rsa.PublicKey) {
	privkey, _ := rsa.GenerateKey(rand.Reader, 4096)
	return privkey, &privkey.PublicKey
}

func privKeyToStr(privkey *rsa.PrivateKey) string {
	privkeyBytes := x509.MarshalPKCS1PrivateKey(privkey)
	privkeyPem := pem.EncodeToMemory(
		&pem.Block{
			Type:  "RSA PRIVATE KEY",
			Bytes: privkeyBytes,
		},
	)
	return string(privkeyPem)
}

func strToPrivKey(privPEM string) (*rsa.PrivateKey, error) {
	block, _ := pem.Decode([]byte(privPEM))
	if block == nil {
		return nil, errors.New("failed to parse PEM block containing the key")
	}

	priv, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		return nil, err
	}

	return priv, nil
}

func pubKeyToStr(pubkey *rsa.PublicKey) (string, error) {
	pubkeyBytes, err := x509.MarshalPKIXPublicKey(pubkey)
	if err != nil {
		return "", err
	}
	pubkeyPem := pem.EncodeToMemory(
		&pem.Block{
			Type:  "RSA PUBLIC KEY",
			Bytes: pubkeyBytes,
		},
	)

	return string(pubkeyPem), nil
}

func strToPubKey(pubPEM string) (*rsa.PublicKey, error) {
	block, _ := pem.Decode([]byte(pubPEM))
	if block == nil {
		return nil, errors.New("failed to parse PEM block containing the key")
	}

	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, err
	}

	switch pub := pub.(type) {
	case *rsa.PublicKey:
		return pub, nil
	default:
		break // fall through
	}
	return nil, errors.New("Key type is not RSA")
}

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

type Message struct {
	Type      string // Client or Noda
	Data      string
	BlockData Block
}

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

	} else {
		log.Println("A New block №" + strconv.Itoa(newBlock.Index) + " is NOT valid \n")

	}
	return false
}

//Consensus

func isBlockValid(newBlock, oldBlock Block) bool {
	if oldBlock.Index+1 != newBlock.Index {

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

//create web

func run() error {
	mux := mux.NewRouter()
	log.Printf("%+v", "Simple Chain v.1.0\n")
	log.Println("Listening on 127.0.0.1:8080")

	s := &http.Server{
		Handler:        mux,
		Addr:           "127.0.0.1:8080",
		ReadTimeout:    10 * time.Second,
		WriteTimeout:   10 * time.Second,
		MaxHeaderBytes: 1 << 20,
	}
	mux.HandleFunc("/", handleGetBlockchain).Methods("GET")
	mux.HandleFunc("/", handleWriteBlock).Methods("POST")

	if err := s.ListenAndServe(); err != nil {
		return err
	}

	return nil
}

// GET Handler getBlockchain (browse at url://127.0.0.1:8080)
func handleGetBlockchain(w http.ResponseWriter, r *http.Request) {
	bytes, err := json.MarshalIndent(Blockchain, "", "  ")
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	io.WriteString(w, string(bytes))
}

//Message is a  separated structure. It is only for Json requestes

//POST handler WriteBlockchain
func handleWriteBlock(w http.ResponseWriter, r *http.Request) {
	var m Message
	var newBlock Block
	decoder := json.NewDecoder(r.Body)
	if err := decoder.Decode(&m); err != nil {
		//respondWithJSON(w, r, http.StatusBadRequest, r.Body)
		return
	}
	defer r.Body.Close()
	//log.Printf("%+v", m.Version)
	switch m.Type {
	case "Client":
		newBlock, err := generateBlock(Blockchain[len(Blockchain)-1], m.Data, m.BlockData.PubKey)
		if err != nil {
			//respondWithJSON(w, r, http.StatusInternalServerError, m)
			return
		}

		if addBlock(newBlock) {
			// send a block to other nodes
			//respondWithJSON(w, r, http.StatusCreated, newBlock)
		}
	case "Noda":
		newBlock.Index = m.BlockData.Index
		newBlock.Timestamp = m.BlockData.Timestamp
		newBlock.Data = m.BlockData.Data
		newBlock.PubKey = m.BlockData.PubKey
		newBlock.PrevHash = m.BlockData.PrevHash
		newBlock.Hash = m.BlockData.Hash
		if addBlock(newBlock) {
			// send a block to other nodes
			respondWithJSON(w, r, http.StatusCreated, newBlock)
		}

	}
	//log.Printf("%+v", m)
}

func respondWithJSON(w http.ResponseWriter, r *http.Request, code int, payload interface{}) {
	response, err := json.MarshalIndent(payload, "", "  ")
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte("HTTP 500: Internal Server Error"))
		return
	}
	w.WriteHeader(code)
	w.Write(response)
}

func main() {
	_, pub := genRsaKeyPair()
	StrPub, _ := pubKeyToStr(pub)
	go func() {
		t := time.Now()
		genesisBlock := Block{0, t.String(), StrPub, "Created by Victor Nelin.", "1", ""}
		//spew.Dump(genesisBlock)
		Blockchain = append(Blockchain, genesisBlock)
		log.Printf("%+v", "Genesis block was created\n")
		log.Printf("%+v", genesisBlock)

	}()
	log.Fatal(run())
}

//fmt.Println(input)
//fmt.Println(num)
