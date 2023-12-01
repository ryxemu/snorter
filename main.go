package main

import (
	"context"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/google/gopacket/pcapgo"
	"github.com/inconshreveable/mousetrap"
)

func main() {
	err := run()
	if err != nil {
		fmt.Println("Failed to run:", err)
		if strings.Contains(err.Error(), "wpcap.dll") {
			fmt.Println("This means winpcap isn't installed. Run https://www.winpcap.org/install/bin/WinPcap_4_1_3.exe to fix this.")
		}
		if !mousetrap.StartedByExplorer() {
			os.Exit(1)
		}
		fmt.Println("Ended program with an error.")
		fmt.Println("Close this window or press CTRL+C to exit.")
		for {
			time.Sleep(1 * time.Second)
		}
	}
	fmt.Println("Ended program successfully.")
}

func run() error {
	deviceName := ""

	devs, err := pcap.FindAllDevs()
	if err != nil {
		return fmt.Errorf("findAllDevices: %w", err)
	}
	i := 0

	devices := []string{}

	suggestID := -1
	suggestedDevice := ""
	for _, device := range devs {
		suggestText := ""
		ipName := ""

		if len(device.Addresses) == 0 {
			continue
		}
		for _, addr := range device.Addresses {
			ip := addr.IP.String()
			if !strings.Contains(ip, ".") {
				continue
			}
			if strings.Index(ip, "127.") == 0 {
				continue
			}
			ipName = ip
			if suggestID == -1 {
				suggestID = i
				suggestText = "(Recommended)"
				suggestedDevice = device.Name
			}
		}

		if len(devices) > 20 {
			continue
		}

		if len(ipName) > 0 {
			ipName = fmt.Sprintf("[%s]", ipName)
		}
		desc := " "
		if len(device.Description) > 0 {
			desc = fmt.Sprintf(" - %s ", device.Description)
		}

		devices = append(devices, fmt.Sprintf("%s %s%s%s", device.Name, ipName, desc, suggestText))
		i++
	}
	fmt.Println("name [ip]")
	fmt.Println("---------")
	for _, dev := range devices {
		fmt.Println(dev)
	}
	if len(suggestedDevice) > 0 {
		fmt.Println("If capturing fails, run with the name above as an argument")
	}

	if len(os.Args) < 2 {
		deviceName = suggestedDevice
	}

	handle, err := pcap.OpenLive(deviceName, 1600, false, pcap.BlockForever)
	if err != nil {
		return fmt.Errorf("openLive: %w", err)
	}
	defer handle.Close()
	fmt.Println("Listening on", deviceName)

	dumpPath := fmt.Sprintf("snorter-%s.pcap", time.Now().Format("2006-01-02-15-04-05"))

	w, err := os.Create(dumpPath)
	if err != nil {
		return fmt.Errorf("create %s: %w", dumpPath, err)
	}
	defer w.Close()

	pcapw := pcapgo.NewWriter(w)
	err = pcapw.WriteFileHeader(1024, layers.LinkTypeEthernet)
	if err != nil {
		return fmt.Errorf("writefileHeader: %w", err)
	}
	fmt.Printf("Dumping snort raw captures to %s\n", dumpPath)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	filter := "not udp port 5353 and udp[0:2] > 1024 and udp[2:2] > 1024 and ether proto 0x0800 and ip[16] < 225"
	err = handle.SetBPFFilter(filter)
	if err != nil {
		return fmt.Errorf("bpfilter %s: %w", filter, err)
	}

	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	for {
		select {
		case <-ctx.Done():
			fmt.Println("Context cancelled")
			return fmt.Errorf("ctx done: %w", ctx.Err())
		case pkt := <-packetSource.Packets():
			err = pcapw.WritePacket(pkt.Metadata().CaptureInfo, pkt.Data())
			if err != nil {
				return fmt.Errorf("dump writePacket: %w", err)
			}
			/*ipv4Layer := psPacket.Layer(layers.LayerTypeIPv4)
			if ipv4Layer == nil {
				return fmt.Errorf("ipv4Layer nil")
			}
			ipv4, ok := ipv4Layer.(*layers.IPv4)
			if !ok {
				return fmt.Errorf("ipv4 assert failure")
			}
			_, err = fd.Write(ipv4.SrcIP.To16())
			if err != nil {
				return fmt.Errorf("write dump header: %w", err)
			}
			_, err = fd.Write([]byte(">"))
			if err != nil {
				return fmt.Errorf("write dump header: %w", err)
			}
			_, err = fd.Write(psPacket.ApplicationLayer().Payload())
			if err != nil {
				return fmt.Errorf("write dump: %w", err)
			}
			_, err = fd.Write([]byte("||"))
			if err != nil {
				return fmt.Errorf("write dump delimiter: %w", err)
			}*/

		}
	}
}
