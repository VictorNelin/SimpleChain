package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"time"
	//"github.com/davecgh/go-spew/spew"

	"github.com/gorilla/mux"
)

type Message struct {
	Type      string // Client or Noda
	Data      string
	BlockData Block
	NodeAddr  []string
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

//wip
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
