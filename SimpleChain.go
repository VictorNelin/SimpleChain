package main

import (
	"bytes"
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
	"net"
	"net/http"
	"os"
	"time"
	//"github.com/davecgh/go-spew/spew"
	"strconv"

	"github.com/gorilla/mux"
)

func bytesToString(data []byte) string {
	return string(data[:])
}
func removeDuplicates(elements []string) []string {

	encountered := map[string]bool{}
	result := []string{}
	for v := range elements {
		if encountered[elements[v]] == true {
		} else {
			encountered[elements[v]] = true
			result = append(result, elements[v])
		}
	}
	return result
}

var nodeList []string

func addNode(newNode string) bool {
	//MyNode := "127.0.0.1:8081"

	for _, enlistNode := range nodeList {
		if enlistNode == newNode {
			fmt.Println("Warning: " + newNode + " is enlisted already")
			return false
		}

	}
	nodeList = removeDuplicates(append(nodeList, newNode))
	fmt.Println("Success: " + newNode + " added")
	return true
}
func addListNodes(newNodeList []string) []string {
	return removeDuplicates(append(nodeList, newNodeList...))
}

//Fix hadler
func annonceBlock(newBlock Block) {

	var msg Message
	msg.Type = "Noda"
	msg.Data = newBlock.Data
	msg.BlockData.Index = newBlock.Index
	msg.BlockData.Timestamp = newBlock.Timestamp
	msg.BlockData.PubKey = newBlock.PubKey
	msg.BlockData.Data = newBlock.Data
	msg.BlockData.Hash = newBlock.Hash
	msg.BlockData.PrevHash = newBlock.PrevHash
	msg.NodeAddr = nil

	encMsgJSON, _ := json.Marshal(msg)
	for _, enlistNode := range removeDuplicates(nodeList) {
		fmt.Println("Sending Block to: " + enlistNode)
		req, _ := http.NewRequest("POST", "http://"+enlistNode, bytes.NewBuffer(encMsgJSON))
		req.Header.Set("Content-Type", "application/json")

	}
}

func reqNodeList() {
	var msg Message

	msg.Type = "Bootstrap"

	encMsgJSON, _ := json.Marshal(msg)

	fmt.Println(string(encMsgJSON))

	for _, enlistNode := range removeDuplicates(nodeList) {
		fmt.Println("Request a List from: " + enlistNode)
		//fmt.Println(enlistNode)
		req, err := http.NewRequest("POST", "http://"+enlistNode, bytes.NewReader(encMsgJSON))
		if err != nil {
			log.Panicln(err)
		}
		//req, err := http.NewRequest("POST", "http://192.168.100.2:8080", bytes.NewBuffer(encMsgJSON))
		req.Header.Set("Content-Type", "application/json")
		client := &http.Client{}
		resp, err := client.Do(req)
		if err != nil {
			log.Println(err)
		}
		var m Message
		defer resp.Body.Close()
		decoder := json.NewDecoder(resp.Body)

		err = decoder.Decode(&m)
		fmt.Println(m.NodeAddr)

		nodeList = addListNodes(m.NodeAddr)
		fmt.Println(m.NodeAddr)
		//fmt.Println(nodeList)

	}

}

//Add Handler
func reqNodeListSilent() {

	ticker := time.NewTicker(time.Second * 5)

	for t := range ticker.C {
		fmt.Println("Tick at", t)
		reqNodeList()

	}
	time.Sleep(time.Second * 500)
	ticker.Stop()
	fmt.Println("Ticker stopped")

}

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
	NodeAddr  []string
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

//Create web-Server
var nodeIP string

func run() error {
	mux := mux.NewRouter()
	log.Printf("%+v", "Simple Chain v.1.2\n")

	/* reader := bufio.NewReader(os.Stdin)
	nodeIP, _ := reader.ReadString('')
	*/

	s := &http.Server{
		Handler:        mux,
		Addr:           nodeIP,
		ReadTimeout:    10 * time.Second,
		WriteTimeout:   10 * time.Second,
		MaxHeaderBytes: 1 << 20,
	}
	log.Println("Listening on " + s.Addr)
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
	fmt.Println("Client's IP is:" + r.RemoteAddr)
	addNode(r.RemoteAddr) //just for test
	io.WriteString(w, string(bytes))
}

//Message is a  separated structure. It is only for Json requestes

//POST handler WriteBlockchain
func handleWriteBlock(w http.ResponseWriter, r *http.Request) {
	var m Message
	var newBlock Block
	decoder := json.NewDecoder(r.Body)
	if err := decoder.Decode(&m); err != nil {

		respondWithJSON(w, r, http.StatusBadRequest, r.Body)
		return
	}

	defer r.Body.Close()
	//log.Printf("%+v", m.Version)

	switch m.Type {
	case "Client":
		newBlock, err := generateBlock(Blockchain[len(Blockchain)-1], m.Data, m.BlockData.PubKey)
		if err != nil {
			respondWithJSON(w, r, http.StatusInternalServerError, m)
			return
		}
		addNode(r.RemoteAddr)
		addBlock(newBlock)
		respondWithJSON(w, r, http.StatusCreated, newBlock)
	case "Noda":
		newBlock.Index = m.BlockData.Index
		newBlock.Timestamp = m.BlockData.Timestamp
		newBlock.PubKey = m.BlockData.PubKey
		newBlock.Data = m.BlockData.Data
		newBlock.Hash = m.BlockData.Hash
		newBlock.PrevHash = m.BlockData.PrevHash
		addNode(r.RemoteAddr)

		if addBlock(newBlock) != false {
			annonceBlock(newBlock)
		}

		respondWithJSON(w, r, http.StatusCreated, newBlock)

	case "Bootstrap":
		// append or merge newlist to existing
		var bootstrapMsg Message

		addNode(r.RemoteAddr)

		//nodeList = addListNodes(m.NodeAddr)
		bootstrapMsg.NodeAddr = nodeList

		respondWithJSON(w, r, http.StatusCreated, bootstrapMsg)

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
	fmt.Print("Enter Node IP and port (IP:port): ")
	fmt.Scanf("%s", &nodeIP)

	go func() {
		t := time.Now()
		genesisBlock := Block{0, t.String(), StrPub, "Created by Victor Nelin.", "1", ""}
		//spew.Dump(genesisBlock)
		Blockchain = append(Blockchain, genesisBlock)
		log.Printf("%+v", "Genesis block was created\n")
		log.Printf("%+v", genesisBlock)

	}()
	go func() {
		host, _ := os.Hostname()
		addrs, _ := net.LookupIP(host)
		for _, addr := range addrs {
			if ipv4 := addr.To4(); ipv4 != nil {

				if addNode(ipv4.String()+":8080") == true {
					addNode("192.168.100.8:8080")

				}

			}
		}
		reqNodeListSilent()
		//fmt.Println(backgrAnnonceList())

	}()
	log.Fatal(run())
}

//fmt.Println(input)
//fmt.Println(num)
