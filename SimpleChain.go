package main

import (
	"bufio"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"time"
	//"github.com/davecgh/go-spew/spew"
	"github.com/gorilla/mux"
)

// Scan input

/* type syncNode interface {

	reqLastBlockNumber () error
	sendLastBlockNumber () error
	reqBlock (int) error
	sendBlock (int) error



} */

type Node struct {
	nodeName string
	pubKey   *rsa.PublicKey
}

var nodeList []Node // do not forget to add genesis node

func addNode(newNode Node) bool {
	for i := 0; i != len(nodeList); {
		if newNode.nodeName != nodeList[i].nodeName {
			i++
		} else {
			fmt.Println("Node has been already added " + newNode.nodeName + "\n")
			return true
		}

	}
	nodeList = append(nodeList, newNode)
	fmt.Println("Node added: " + newNode.nodeName + "\n")
	//log.Printf("%+v", newNode)
	return true
}

func GenPairs() bool {
	var N Node
	//Setting Up a node
	reader := bufio.NewReader(os.Stdin)
	// Prompt and read
	fmt.Print("Enter Node ID: ")
	N.nodeName, _ = reader.ReadString('\n')

	nodePrivKey, err := rsa.GenerateKey(rand.Reader, 2048)

	if err != nil {
		fmt.Println(err.Error)
		return false
	}

	N.pubKey = &nodePrivKey.PublicKey

	fmt.Println("Private Key : ", nodePrivKey)
	fmt.Println("Public key ", N.pubKey)

	res := addNode(N)
	if res != true {
		fmt.Println("Could not add Node")
	}

	return true
}

// Block structure
type Block struct {
	Index     int
	Timestamp string
	Data      string
	Hash      string
	PrevHash  string
}

// Blockchain is a slice of structure
var Blockchain []Block

func calculateHash(block Block) string {
	record := string(block.Index) + block.Timestamp + string(block.Data) + block.PrevHash
	h := sha256.New()
	h.Write([]byte(record))
	hashed := h.Sum(nil)
	return hex.EncodeToString(hashed)
}

func generateBlock(oldBlock Block, data string) (Block, error) {

	var newBlock Block

	t := time.Now()

	newBlock.Index = oldBlock.Index + 1
	newBlock.Timestamp = t.String()
	newBlock.Data = data
	newBlock.PrevHash = oldBlock.Hash
	newBlock.Hash = calculateHash(newBlock)

	return newBlock, nil
}

func addBlock(newBlock Block) bool {
	lastBlock := Blockchain[len(Blockchain)-1]
	if isBlockValid(newBlock, lastBlock) {
		newBlockchain := append(Blockchain, newBlock)
		replaceChain(newBlockchain)

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

// GET Handler getBlockchain
func handleGetBlockchain(w http.ResponseWriter, r *http.Request) {
	bytes, err := json.MarshalIndent(Blockchain, "", "  ")
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	io.WriteString(w, string(bytes))
}

//Message is a  separated structure. It is only for Json requestes
type Message struct {
	Type       string // Node or Data
	Data       string
	NodeName   string
	NodePubKey rsa.PublicKey //FUCKING SHIT

	//lastBlockinfo

}

//POST handler WriteBlockchain
func handleWriteBlock(w http.ResponseWriter, r *http.Request) {
	var m Message

	decoder := json.NewDecoder(r.Body)
	if err := decoder.Decode(&m); err != nil {
		respondWithJSON(w, r, http.StatusBadRequest, r.Body)
		return
	}
	defer r.Body.Close()
	//log.Printf("%+v", m.Version)
	switch m.Type {
	case "Data":

		newBlock, err := generateBlock(Blockchain[len(Blockchain)-1], m.Data)
		if err != nil {
			respondWithJSON(w, r, http.StatusInternalServerError, m)
			return
		}

		if addBlock(newBlock) {
			// send a block to other nodes
		}

		respondWithJSON(w, r, http.StatusCreated, newBlock)
	case "Node":
		var newNode Node
		newNode.nodeName = m.NodeName
		newNode.pubKey = &m.NodePubKey
		addNode(newNode)
		respondWithJSON(w, r, http.StatusCreated, newNode)

	default:
		log.Printf("%+v", m.Type)
	}

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

	//dataJson := "test_data"
	if GenPairs() != true {

		fmt.Println("Node couldn't intilize")

	}

	go func() {
		t := time.Now()
		genesisBlock := Block{0, t.String(), "Created by Victor Nelin.", "", ""}
		//spew.Dump(genesisBlock)
		Blockchain = append(Blockchain, genesisBlock)
		log.Printf("%+v", "Genesis block was created\n")
		log.Printf("%+v", genesisBlock)

	}()
	log.Fatal(run())
}

//fmt.Println(input)
//fmt.Println(num)
