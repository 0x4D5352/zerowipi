package main

import (
	"fmt"
	"log"
	"os/exec"
	"strconv"
	"strings"
	"sync"
	"time"
)

type NMCLIOutput struct {
	Name      string
	SSID      string
	SSID_Hex  string
	BSSID     string
	Mode      string
	Chan      int
	Freq      int // in MHz
	Rate      int // in Mbit/s
	Bandwidth int // in MHz
	Signal    int
	Bars      string
	Security  string
	WPAFlags  string
	RSNFlags  string
	Device    string
	Active    string
	InUse     bool
	DBusPath  string
}

func main() {
	// TODO: implement graceful shutdown
	fmt.Println("starting...")
	var wg sync.WaitGroup
	rawLines := make(chan string, 256)
	// parsedLines := make(chan NMCLIOutput, 256)
	wg.Add(2)
	go scanWAP(rawLines, &wg)
	go parseWAP(rawLines, &wg)
	// go parseWAP(rawLines, parsedLines, &wg)
	wg.Wait()
	fmt.Println("oh no i stopped running")
}

// TODO: write a comparable version using iwlist and ip -j addr to see if that performs better
func scanWAP(raw chan string, wg *sync.WaitGroup) {
	defer wg.Done()
	result := ""
	for {
		out, err := exec.Command("nmcli", "-t", "-c", "no", "-f", "ALL", "dev", "wifi", "list").Output()
		if err != nil {
			log.Fatalf("failed to exec nmcli: %v", err)
		}
		// fmt.Printf("%s\n", out)
		outString := string(out)
		if result != outString {
			result = outString
			lines := strings.Lines(result)
			for line := range lines {
				raw <- line
			}
		}
		time.Sleep(time.Second * 5)
	}
}

// func parseWAP(raw chan string, parsed chan NMCLIOutput, wg *sync.WaitGroup) {
func parseWAP(raw chan string, wg *sync.WaitGroup) {
	defer wg.Done()
	for {
		s := <-raw
		escapedBSSID := strings.ReplaceAll(s, "\\:", ";")
		splitResult := strings.Split(escapedBSSID, ":")
		c, err := strconv.Atoi(splitResult[5])
		if err != nil {
			log.Fatalf("failed to parse WAP channel: %v", err)
		}
		splitFreq := strings.Split(splitResult[6], " ")
		f, err := strconv.Atoi(splitFreq[0])
		if err != nil {
			log.Fatalf("failed to parse WAP frequency: %v", err)
		}
		splitRate := strings.Split(splitResult[7], " ")
		r, err := strconv.Atoi(splitRate[0])
		if err != nil {
			log.Fatalf("failed to parse WAP rate: %v", err)
		}
		splitBandwidth := strings.Split(splitResult[8], " ")
		b, err := strconv.Atoi(splitBandwidth[0])
		if err != nil {
			log.Fatalf("failed to parse WAP bandwidth: %v", err)
		}
		splitSignal := strings.Split(splitResult[9], " ")
		si, err := strconv.Atoi(splitSignal[0])
		if err != nil {
			log.Fatalf("failed to parse WAP signal: %v", err)
		}
		var iu bool
		if splitResult[16] == "*" {
			iu = true
		}
		result := NMCLIOutput{
			Name:      splitResult[0],
			SSID:      splitResult[1],
			SSID_Hex:  splitResult[2],
			BSSID:     strings.ReplaceAll(splitResult[3], ";", ":"),
			Mode:      splitResult[4],
			Chan:      c,
			Freq:      f,
			Rate:      r,
			Bandwidth: b,
			Signal:    si,
			Bars:      splitResult[10],
			Security:  splitResult[11],
			WPAFlags:  splitResult[12],
			RSNFlags:  splitResult[13],
			Device:    splitResult[14],
			Active:    splitResult[15],
			InUse:     iu,
			DBusPath:  splitResult[17],
		}
		fmt.Printf("%v+\n", result)
		// parsed <- result
	}
}
