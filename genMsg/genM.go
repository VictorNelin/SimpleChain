package main

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
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

type Message struct {
	Type      string // Client or Noda
	Data      string
	BlockData Block
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

func main() {
	//go log.Fatal(run())
	/* reader := bufio.NewReader(os.Stdin)

	fmt.Print("Enter a message: ")
	msg, _ := reader.ReadString('\n') */

	// Create the keys
	_, pub := genRsaKeyPair()
	strPubKey, _ := pubKeyToStr(pub)
	//gen rnd json

	ticker := time.NewTicker(time.Second * 5)
	go func() {
		i := 1
		for t := range ticker.C {
			fmt.Println("Tick at", t)
			tn := time.Now()
			i++
			msgJSON := Message{
				Type: "Client",
				Data: "client Data" + strconv.Itoa(i),
				BlockData: Block{
					Index:     i,
					Timestamp: tn.String(),
					PubKey:    strPubKey,
					Data:      "Block data" + strconv.Itoa(i),
					Hash:      "",
					PrevHash:  "",
				},
			}

			encMsgJSON, err := json.Marshal(msgJSON)
			fmt.Println(string(encMsgJSON))

			/* if err != nil {
				fmt.Fprintf(w, "Error: %s", err)
			} */

			//send
			req, err := http.NewRequest("POST", "http://127.0.0.1:8080", bytes.NewBuffer(encMsgJSON))
			req.Header.Set("Content-Type", "application/json")
			client := &http.Client{}
			resp, err := client.Do(req)
			if err != nil {
				log.Fatal(err)
			}
			body, err := ioutil.ReadAll(resp.Body)
			fmt.Println("Response: ", string(body))
			resp.Body.Close()
		}

	}()
	time.Sleep(time.Second * 50)
	ticker.Stop()
	fmt.Println("Ticker stopped")

}