package main

import (
	"fmt"
	"net"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

func main() {
	// Define the destination IP address and UDP ports to filter
	destinationIP := net.IPv4(255, 255, 255, 255)
	sourcePort := uint16(14236)
	destinationPort := uint16(14235)

	// Get a list of available network interfaces for sniffing
	devices, err := pcap.FindAllDevs()
	if err != nil {
		panic(err)
	}

	// Print the interfaces for debugging purposes
	// fmt.Println("Available interfaces:")
	// for _, device := range devices {
	//     fmt.Println(device)
	// }

	// Choose the correct interface for sniffing
	var handle *pcap.Handle
	for _, device := range devices {
		if len(device.Addresses) > 0 {
			handle, err = pcap.OpenLive(device.Name, 1600, true, pcap.BlockForever)
			if err == nil {
				break
			}
		}
	}
	if handle == nil {
		panic("No suitable interface found")
	}
	defer handle.Close()

	// Print the chosen interface
	// fmt.Println("Chosen interface:", handle)

	fmt.Println("Listening...")

	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())

	for packet := range packetSource.Packets() {
		// Parse the packet as an Ethernet packet
		if ethernetPacket := packet.Layer(layers.LayerTypeEthernet); ethernetPacket != nil {
			if ipv4Packet := packet.Layer(layers.LayerTypeIPv4); ipv4Packet != nil {
				ip, _ := ipv4Packet.(*layers.IPv4)

				// Check if the packet has a UDP layer
				if udpLayer := packet.Layer(layers.LayerTypeUDP); udpLayer != nil {
					udp, _ := udpLayer.(*layers.UDP)

					// Check if the packet matches the specified destination IP address and UDP ports
					if ip.DstIP.Equal(destinationIP) && udp.SrcPort == layers.UDPPort(sourcePort) && udp.DstPort == layers.UDPPort(destinationPort) {
						fmt.Println("Miner IP:", ip.SrcIP)
					} else {
						// Filter out non-matching packets
						// fmt.Printf("Non-matching packet: %s:%d -> %s:%d\n", ip.SrcIP, udp.SrcPort, ip.DstIP, udp.DstPort)
					}
				}
			}
		}
	}
}
