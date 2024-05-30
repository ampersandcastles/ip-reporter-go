package main

import (
	"fmt"
	"log"
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
		log.Fatalf("Error finding devices: %v", err)
	}

	// Print the interfaces for debugging purposes
	fmt.Println("Available interfaces:")
	for _, device := range devices {
		fmt.Println(device.Name)
	}

	// Choose the correct interface for sniffing
	var handle *pcap.Handle
	for _, device := range devices {
		if len(device.Addresses) > 0 {
			handle, err = pcap.OpenLive(device.Name, 1600, true, pcap.BlockForever)
			if err == nil {
				fmt.Println("Using interface:", device.Name)
				break
			} else {
				fmt.Printf("Error opening device %s: %v\n", device.Name, err)
			}
		}
	}
	if handle == nil {
		log.Fatal("No suitable interface found")
	}
	defer handle.Close()

	// Construct the BPF filter string
	filter := fmt.Sprintf("udp and src port %d and dst port %d and dst host %s", sourcePort, destinationPort, destinationIP.String())

	// Apply the BPF filter to the handle
	err = handle.SetBPFFilter(filter)
	if err != nil {
		log.Fatalf("Error setting BPF filter: %v", err)
	}

	fmt.Println("Listening...")

	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())

	for packet := range packetSource.Packets() {
		// Parse the packet as an Ethernet packet
		if ethernetPacket := packet.Layer(layers.LayerTypeEthernet); ethernetPacket != nil {
			eth, _ := ethernetPacket.(*layers.Ethernet)

			if ipv4Packet := packet.Layer(layers.LayerTypeIPv4); ipv4Packet != nil {
				ip, _ := ipv4Packet.(*layers.IPv4)

				// Check if the packet has a UDP layer
				if udpLayer := packet.Layer(layers.LayerTypeUDP); udpLayer != nil {
					udp, _ := udpLayer.(*layers.UDP)

					// Check if the packet matches the specified destination IP address and UDP ports
					if ip.DstIP.Equal(destinationIP) && udp.SrcPort == layers.UDPPort(sourcePort) && udp.DstPort == layers.UDPPort(destinationPort) {
						fmt.Println("Miner IP:", ip.SrcIP)
						fmt.Println("Miner MAC:", eth.SrcMAC)
					}
				}
			}
		}
	}
}
