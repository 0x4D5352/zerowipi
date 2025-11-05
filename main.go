package main

import (
	"fmt"
	"log"
	"os/exec"
	"strconv"
	"strings"
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
	go scanWAP()
}

func scanWAP() {
	result := ""
	for {
		out, err := exec.Command("nmcli", "-t", "-f", "ALL", "dev", "wifi", "list").Output()
		if err != nil {
			log.Fatalf("failed to exec nmcli: %v", err)
		}
		fmt.Printf("%s\n", out)
		outString := string(out)
		if result != outString {
			result = outString
			go parseWAP(outString)
		}
		time.Sleep(time.Minute * 5)
	}
}

func parseWAP(s string) {
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
}
