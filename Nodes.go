package main

import (
	"fmt"
	"log"
	"time"

	"github.com/franela/goreq"
	//"github.com/davecgh/go-spew/spew"
)

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
