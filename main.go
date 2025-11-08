package main

import (
	// "database/sql"
	"context"
	"fmt"
	"log/slog"
	"os"

	// "os"
	"os/exec"

	"os/signal"
	"strconv"
	"strings"

	"syscall"
	"time"

	"golang.org/x/sync/errgroup"
	// _ "modernc.org/sqlite"
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
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelInfo}))
	logger.Info("starting...")

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	const (
		rbuf = 256
		pbuf = 256
		pw   = 4
		cw   = 2
		// bs   = 256
		// fs   = 10 * time.Millisecond
		d = time.Second * 10
	)

	// TODO: add db handling

	// db, err := sql.Open("sqlite", "file:zwp.db?cache=shared&mode=rwc")
	// if err != nil {
	// 	log.Fatal(err)
	// }
	// if _, err := db.Exec(`
	// PRAGMA journal_mode=WAL;
	// PRAGMA synchronous=NORMAL;
	// PARGMA busy_timeout=2000;
	// `); err != nil {
	// 	_ = db.Close()
	// 	log.Fatal(err)
	// }

	raw := make(chan string, rbuf)
	parsed := make(chan NMCLIOutput, pbuf)

	g, ctx := errgroup.WithContext(ctx)

	g.Go(func() error { return scanWAP(d, raw, ctx, logger) })
	for range pw {
		g.Go(func() error { return parseWAP(raw, parsed, ctx, logger) })
	}
	//TODO: add funtion to spin up DB processing between these two
	for range cw {
		g.Go(func() error { return FilterWAPSecurity(parsed, ctx, logger) })
	}
	g.Wait()
	logger.Info("complete")
}

func scanWAP(d time.Duration, out chan string, ctx context.Context, logger *slog.Logger) error {
	logger.Info("starting scanner")
	ticker := time.NewTicker(d)
	defer ticker.Stop()
	defer close(out)
	result := ""
	scan := func() error {
		logger.Debug("starting scan")
		raw, err := exec.Command("nmcli", "-t", "-c", "no", "-f", "ALL", "dev", "wifi", "list", "--rescan", "yes").Output()
		if err != nil {
			return fmt.Errorf("failed to exec nmcli: %v", err)
		}
		outString := string(raw)
		logger.Debug("outstring received", "outString", outString)
		if result != outString {
			result = outString
			lines := strings.Lines(result)
			for line := range lines {
				out <- line
			}
		}
		return nil

	}
	err := scan()
	if err != nil {
		return err
	}
	for {
		select {
		case <-ctx.Done():
			logger.Info("closing scanner gracefully")
			return ctx.Err()
		case <-ticker.C:
			err := scan()
			if err != nil {
				return err
			}
		}
	}
}

func parseWAP(in chan string, out chan NMCLIOutput, ctx context.Context, logger *slog.Logger) error {
	defer close(out)
	logger.Info("starting parser")
	for {
		select {
		case <-ctx.Done():
			logger.Info("closing parser gracefully")
			return ctx.Err()
		case <-in:
			s := <-in
			logger.Debug("line received", "line", s)
			escapedBSSID := strings.ReplaceAll(s, "\\:", ";")
			splitResult := strings.Split(escapedBSSID, ":")
			c, err := strconv.Atoi(splitResult[5])
			if err != nil {
				return fmt.Errorf("failed to parse WAP channel: %v", err)
			}
			splitFreq := strings.Split(splitResult[6], " ")
			f, err := strconv.Atoi(splitFreq[0])
			if err != nil {
				return fmt.Errorf("failed to parse WAP frequency: %v", err)
			}
			splitRate := strings.Split(splitResult[7], " ")
			r, err := strconv.Atoi(splitRate[0])
			if err != nil {
				return fmt.Errorf("failed to parse WAP rate: %v", err)
			}
			splitBandwidth := strings.Split(splitResult[8], " ")
			b, err := strconv.Atoi(splitBandwidth[0])
			if err != nil {
				return fmt.Errorf("failed to parse WAP bandwidth: %v", err)
			}
			splitSignal := strings.Split(splitResult[9], " ")
			si, err := strconv.Atoi(splitSignal[0])
			if err != nil {
				return fmt.Errorf("failed to parse WAP signal: %v", err)
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
			out <- result
		}
	}
}

func FilterWAPSecurity(in chan NMCLIOutput, ctx context.Context, logger *slog.Logger) error {
	logger.Info("starting filter")
	for {
		select {
		case <-ctx.Done():
			logger.Info("closing filter gracefully")
			return ctx.Err()
		case <-in:
			wap := <-in
			switch wap.Security {
			case "--":
				fmt.Printf("Pulic WAP a, SSID: %s; MAC: %s\n", wap.SSID, wap.BSSID)
			case "":
				fmt.Printf("Pulic WAP b, SSID: %s; MAC: %s\n", wap.SSID, wap.BSSID)
			case "WPA":
				fmt.Printf("WPA Security, SSID: %s; MAC: %s\n", wap.SSID, wap.BSSID)
			case "WPA2":
				fmt.Printf("WPA2 Security, SSID: %s; MAC: %s\n", wap.SSID, wap.BSSID)
			case "WPA3":
				fmt.Printf("WPA3 Security, SSID: %s; MAC: %s\n", wap.SSID, wap.BSSID)
			case "WEP":
				fmt.Printf("WEP Security, SSID: %s; %s\n", wap.SSID, wap.BSSID)
			default:
				fmt.Printf("Unknown Security, SSID: %s; WAP: %s; Security: %s\n", wap.SSID, wap.BSSID, wap.Security)
			}
		}
	}
}
