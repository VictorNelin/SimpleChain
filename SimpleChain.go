package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"log"
	"net"
	"os"
	"time"
	//"github.com/davecgh/go-spew/spew"
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

//Fix hadler

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
