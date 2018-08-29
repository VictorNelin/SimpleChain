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

	"github.com/franela/goreq"
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
func cutSlice(inputSlice []string, delElem string) []string {
	for i, v := range inputSlice {
		if v == delElem {
			return append(inputSlice[:i], inputSlice[i+1:]...)
		}
	}
	return inputSlice
}

var nodeList []string

func addNode(newNode string) bool {

	for _, enlistNode := range nodeList {
		if enlistNode == newNode {
			log.Println("Warning: " + newNode + " is enlisted already")
			return false
		}

	}
	nodeList = removeDuplicates(append(nodeList, newNode))
	log.Println("Success: " + newNode + " added")
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

func getAliveNodes(checkNodeList []string) []string {

	var msg Message
	msg.Type = "Alive"
	availableNodes := checkNodeList
	for _, enlistNode := range removeDuplicates(checkNodeList) {
		if enlistNode != nodeIP {
			goreq.SetConnectTimeout(100 * time.Millisecond)
			res, err := goreq.Request{
				Method:  "POST",
				Uri:     "http://" + enlistNode,
				Timeout: 90 * time.Millisecond,
				Body:    msg,
			}.Do()
			if err != nil {
				//Cut a dead Node from a Node list
				log.Println("Node : " + enlistNode + " is dead and would be deleted from a Alive Node list.")
				nodeList = cutSlice(nodeList, enlistNode)
				availableNodes = cutSlice(availableNodes, enlistNode)
				log.Println("Availible nodes", availableNodes)
				return availableNodes

			}

			var recivedM Message
			if err := res.Body.FromJsonTo(&recivedM); err != nil {
				nodeList = cutSlice(nodeList, enlistNode)
				availableNodes = cutSlice(availableNodes, enlistNode)
				fmt.Println(err)
			}
			if recivedM.Data != "True" {
				log.Println("Node : " + enlistNode + " is not response correct to Alive request and would be deleted from a Alive Node list.")
				nodeList = cutSlice(nodeList, enlistNode)
				availableNodes = cutSlice(availableNodes, enlistNode)
			}

			/* log.Println("Answer from: ", enlistNode, ". ", recivedM.NodeAddr)
			nodeList = addListNodes(recivedM.NodeAddr) */
		}
	}

	return availableNodes
}

func reqNodeList(reqList []string) {
	//Fulfilling a Message to request with an availiable nodelist
	var msg Message
	msg.Type = "Bootstrap"
	msg.NodeAddr = reqList
	//Try to send a request to all enlisted Nodes
	for _, enlistNode := range removeDuplicates(reqList) {
		if enlistNode != nodeIP {
			trig := 0
			goreq.SetConnectTimeout(100 * time.Millisecond)
			res, err := goreq.Request{
				Method:  "POST",
				Uri:     "http://" + enlistNode,
				Timeout: 90 * time.Millisecond,
				Body:    msg,
			}.Do()
			if err != nil {
				//Cut a dead Node from a Node list
				log.Println("Host: " + enlistNode + " is not responding and would be deleted from a Node list.")
				nodeList = cutSlice(nodeList, enlistNode)
				msg.NodeAddr = cutSlice(reqList, enlistNode)
				/* break */
				trig = 1
			}
			if trig != 1 {
				var recivedM Message
				if err := res.Body.FromJsonTo(&recivedM); err != nil {
					nodeList = cutSlice(nodeList, enlistNode)
					msg.NodeAddr = cutSlice(reqList, enlistNode)
					fmt.Println(err)
				}
				log.Println("Answer from: ", enlistNode, ". ", recivedM.NodeAddr)
				nodeList = addListNodes(recivedM.NodeAddr)
			}
		}
	}

}

func addDefaultNodes() {

	addNode("192.168.100.9:8080")
	addNode("192.168.100.7:8080")
	addNode("192.168.100.2:8080")
	addNode("192.168.100.6:8080")
}

func reqNodeListSilent() {

	ticker := time.NewTicker(time.Second * 60)

	for t := range ticker.C {
		fmt.Println("Silent Node discovering", t)
		addDefaultNodes()
		reqNodeList(getAliveNodes(nodeList))
		log.Println("Current node list: ", nodeList)

	}
	time.Sleep(time.Second * 80000)
	/* ticker.Stop()
	fmt.Println("Ticker stopped") */

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
	log.Printf("%+v", "Simple Chain v.1.5a\n")

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

		log.Println("Responding to: " + r.RemoteAddr)
		var respMsg Message
		respMsg.NodeAddr = nodeList // send only alive nodes?

		nodeList = addListNodes(getAliveNodes(m.NodeAddr))
		log.Println("Nodes has been recieved : ", m.NodeAddr)
		respondWithJSON(w, r, http.StatusCreated, respMsg)

	case "Alive":

		log.Println("Responding Alive to: " + r.RemoteAddr)
		var respMsg Message
		respMsg.Data = "True"
		respondWithJSON(w, r, http.StatusCreated, respMsg)

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
		//Bootstrap Nodes
		addNode(nodeIP)
		addDefaultNodes()
		//Discovering an interfaces
		host, _ := os.Hostname()
		addrs, _ := net.LookupIP(host)
		for _, addr := range addrs {
			if ipv4 := addr.To4(); ipv4 != nil {

				if addNode(ipv4.String()+":8080") != true {
					log.Println("Can't add a Node to a List: " + ipv4.String())
				}
			}
		}

		//Run a Silence discovery
		reqNodeListSilent()

	}()
	log.Fatal(run())
}

//fmt.Println(input)
//fmt.Println(num)
