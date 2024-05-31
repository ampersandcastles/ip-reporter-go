package main

import (
	"fmt"
	"os"
	"os/exec"
	"strings"
	"sync"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/app"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/dialog"
	"fyne.io/fyne/v2/widget"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

var (
	destinationIP   = "255.255.255.255"
	sourcePort      = uint16(14236)
	destinationPort = uint16(14235)
	username        = "root"
	password        = "root"
	packetChannel   = make(chan gopacket.Packet)
	listening       = false
	listeningMutex  sync.Mutex
	tree            *widget.Table
	ipAddresses     []string
	macAddresses    []string
	statusLabel     *widget.Label
)

func main() {
	myApp := app.New()
	myWindow := myApp.NewWindow("IP Reporter")

	ipAddresses = make([]string, 0)
	macAddresses = make([]string, 0)

	tree = widget.NewTable(
		func() (int, int) { return len(ipAddresses), 2 },
		func() fyne.CanvasObject { return widget.NewLabel("") },
		func(id widget.TableCellID, o fyne.CanvasObject) {
			switch id.Col {
			case 0:
				o.(*widget.Label).SetText(ipAddresses[id.Row])
			case 1:
				o.(*widget.Label).SetText(macAddresses[id.Row])
			}
		},
	)
	tree.OnSelected = func(id widget.TableCellID) {
		ip := ipAddresses[id.Row]
		url := fmt.Sprintf("http://%s:%s@%s", username, password, ip)
		dialog.ShowConfirm("Open in Browser", "Do you want to open "+url+" in the default browser?", func(b bool) {
			if b {
				openBrowser(url)
			}
		}, myWindow)
	}

	startButton := widget.NewButton("Start", func() {
		toggleListening()
	})

	exportButton := widget.NewButton("Export", func() {
		dialog.ShowFileSave(func(file fyne.URIWriteCloser, err error) {
			if err == nil && file != nil {
				exportData(file)
			}
		}, myWindow)
	})

	statusLabel = widget.NewLabel("Stopped")

	content := container.NewVBox(
		tree,
		startButton,
		exportButton,
		statusLabel,
	)

	myWindow.SetContent(content)
	myWindow.Resize(fyne.NewSize(600, 400))
	myWindow.ShowAndRun()
}

func toggleListening() {
	listeningMutex.Lock()
	defer listeningMutex.Unlock()

	if !listening {
		go listenForPackets()
		statusLabel.SetText("Listening...")
		listening = true
	} else {
		statusLabel.SetText("Stopped")
		listening = false
	}
}

func getNetworkInterface() (string, error) {
	// Check if Ethernet is available
	eth, err := pcap.FindAllDevs()
	if err != nil {
		return "", fmt.Errorf("error finding devices: %v", err)
	}
	for _, device := range eth {
		if device.Name == "eth0" {
			return "eth0", nil
		}
		if device.Name == "wlan0" {
			return "wlan0", nil
		}
	}
	return "", fmt.Errorf("no suitable network interfaces found")
}

func listenForPackets() {
	interfaceName, err := getNetworkInterface()
	if err != nil {
		fmt.Println("Error:", err)
		return
	}
	handle, err := pcap.OpenLive(interfaceName, 1600, true, pcap.BlockForever)
	if err != nil {
		fmt.Println("Error opening device:", err)
		return
	}
	defer handle.Close()

	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	for packet := range packetSource.Packets() {
		if !listening {
			break
		}
		extractPacketInfo(packet)
	}
}

func extractPacketInfo(packet gopacket.Packet) {
	ipLayer := packet.Layer(layers.LayerTypeIPv4)
	udpLayer := packet.Layer(layers.LayerTypeUDP)
	if ipLayer == nil || udpLayer == nil {
		return
	}

	ip, _ := ipLayer.(*layers.IPv4)
	udp, _ := udpLayer.(*layers.UDP)
	if ip.DstIP.String() == destinationIP && uint16(udp.SrcPort) == sourcePort && uint16(udp.DstPort) == destinationPort {
		ethernetLayer := packet.Layer(layers.LayerTypeEthernet)
		ethernetPacket, _ := ethernetLayer.(*layers.Ethernet)

		ipAddresses = append(ipAddresses, ip.SrcIP.String())
		macAddresses = append(macAddresses, ethernetPacket.SrcMAC.String())
		tree.Refresh()
	}
}

func exportData(file fyne.URIWriteCloser) {
	defer file.Close()
	for i := range ipAddresses {
		line := fmt.Sprintf("IP Address: %s, MAC Address: %s\n", ipAddresses[i], macAddresses[i])
		file.Write([]byte(line))
	}
	statusLabel.SetText("Data exported")
}

func openBrowser(url string) {
	var cmd string
	var args []string
	switch strings.ToLower(strings.Split(os.Getenv("OSTYPE"), "_")[0]) {
	case "windows":
		cmd = "rundll32"
		args = []string{"url.dll,FileProtocolHandler", url}
	case "darwin":
		cmd = "open"
		args = []string{url}
	default:
		cmd = "xdg-open"
		args = []string{url}
	}
	exec.Command(cmd, args...).Start()
}
