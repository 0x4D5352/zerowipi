package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha1"
	"database/sql"
	"encoding/hex"
	"io"

	// "fmt"
	"log/slog"
	"os"

	"os/exec"

	"os/signal"
	"strconv"
	"strings"

	"syscall"
	"time"

	"golang.org/x/sync/errgroup"
	_ "modernc.org/sqlite"
)

// NMCLI Exit Codes
const (
	ExitSuccess                           = 0  // Success - indicats the operation succeeded.
	ExitUnknownError                      = 1  // Unknown or unspecified error.
	ExitInvalidInputError                 = 2  // Invalid user input, wrong nmcli invocation.
	ExitTimeoutError                      = 3  // Timeout expired (see --wait option).
	ExitConnectionActivationFailedError   = 4  // Connection activation failed.
	ExitConnectionDeactivationFailedError = 5  // Connection deactivation failed.
	ExitDisconnectFailedError             = 6  // Disconnecting device failed
	ExitConnectionDeletionFailedError     = 7  // Connection deletion failed.
	ExitNetworkManagerNotRunningError     = 8  // NetworkManager is not running.
	ExitDoesNotExistError                 = 10 // Connection, device, or access point does not exist.
	ExitFileNameExpectedError             = 65 // When used with --complete-args option, a file name is expected to follow.
)

type NMCLIOutput struct {
	SSID      string
	SSID_Hex  string
	BSSID     string
	Mode      string
	Chan      int
	Freq      int // in MHz
	Rate      int // in Mbit/s
	Bandwidth int // in MHz
	Signal    int
	Security  string
	WPAFlags  string
	RSNFlags  string
	Device    string
	Active    string
	InUse     bool
	DBusPath  string
}

type DBChange struct {
	Row      NMCLIOutput
	Upserted bool
}

func main() {
	// config settings
	// TODO: put in a config file instead of main func consts
	const (
		rawBuffer       = 256
		parsedBuffer    = 256
		committedBuffer = 256
		parserWorkers   = 4
		filterWorkers   = 2
		bufferSize      = 256
		flushEvery      = time.Second * 1
		scanEvery       = time.Second * 30
		connectEvery    = time.Minute * 1
		logLevel        = slog.LevelInfo
	)

	f, err := os.OpenFile("zwp.log", os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0666)
	if err != nil {
		slog.Error("failed to open log file", "error", err)
		return
	}
	defer f.Close()
	multiWriter := io.MultiWriter(f, os.Stderr)
	handler := slog.NewTextHandler(multiWriter, &slog.HandlerOptions{Level: logLevel})
	logger := slog.New(handler)
	slog.SetDefault(logger)
	logger.Info("starting...")

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	db, err := sql.Open("sqlite", "file:zwp.db?cache=shared&mode=rwc")
	if err != nil {
		logger.Error("failed to open db", "error", err)
		os.Exit(1)
	}
	if err := initDB(db); err != nil {
		logger.Error("failed to initialize db schema", "error", err)
		os.Exit(1)
	}
	defer db.Close()

	raw := make(chan string, rawBuffer)
	parsed := make(chan NMCLIOutput, parsedBuffer)
	committed := make(chan DBChange, committedBuffer)

	group, ctx := errgroup.WithContext(ctx)

	group.Go(func() error { return scanWAP(scanEvery, raw, ctx, logger) })
	for range parserWorkers {
		group.Go(func() error { return parseWAP(raw, parsed, ctx, logger) })
	}
	group.Go(func() error { return writeWAPs(parsed, committed, db, bufferSize, flushEvery, ctx, logger) })
	for range filterWorkers {
		group.Go(func() error { return logWAPs(committed, ctx, logger) })
	}
	group.Go(func() error { return connectToPublicWAPs(connectEvery, ctx, logger, db) })
	if err := group.Wait(); err != nil && err != context.Canceled {
		logger.Error("pipeline stopped with error", "err", err)
	}
	logger.Info("complete")
}

func scanWAP(d time.Duration, out chan string, ctx context.Context, logger *slog.Logger) error {
	logger.Debug("starting scanner")
	defer close(out)
	ticker := time.NewTicker(d)
	defer ticker.Stop()
	var lastHash string
	// these subfunctions could probably be combined, but felt better to split at the time
	run := func() []byte {
		logger.Debug("starting scan")
		raw, err := exec.CommandContext(ctx, "nmcli", "-t", "-c", "no", "-f", "ALL", "dev", "wifi", "list", "--rescan", "yes").Output()
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			logger.Error("failed to exec nmcli", "error", err)
			return nil
		}
		outString := string(raw)
		logger.Debug("outstring received", "outString", outString)
		return raw

	}
	scan := func() {
		data := run()
		if len(data) == 0 {
			return
		}
		sum := sha1.Sum(data)
		hx := hex.EncodeToString(sum[:])
		if hx == lastHash {
			return
		}
		lastHash = hx

		sc := bufio.NewScanner(bytes.NewReader(data))
		for sc.Scan() {
			line := strings.TrimSpace(sc.Text())
			if line == "" {
				continue
			}
			out <- line
		}
		if err := sc.Err(); err != nil {
			logger.Error("io scanner error", "error", err)
		}

	}
	scan()
	for {
		select {
		case <-ctx.Done():
			logger.Debug("closing scanner gracefully")
			return ctx.Err()
		case <-ticker.C:
			scan()
		}
	}
}

func parseWAP(in chan string, out chan NMCLIOutput, ctx context.Context, logger *slog.Logger) error {
	logger.Debug("starting parser")
	for {
		select {
		case <-ctx.Done():
			logger.Debug("closing parser gracefully")
			return ctx.Err()
		case s, ok := <-in:
			if !ok {
				return nil
			}
			logger.Debug("line received", "line", s)
			s = strings.TrimSpace(s)
			if s == "" || strings.HasPrefix(s, "Error:") {
				continue
			}

			// handling escaped colons from BSSID and colon-delimited nmcli output
			tmp := strings.ReplaceAll(s, `\:`, "\x00")
			fields := strings.Split(tmp, ":")
			if len(fields) < 18 {
				logger.Warn("incorrect number of fields found", "len(fields)", len(fields), "fields", fields)
				continue
			}

			// helper function for certain numeric fields
			atoiFirst := func(x string, t string) (int, bool) {
				parts := strings.Fields(x)
				if len(parts) == 0 {
					logger.Warn("couldn't parse string", "str", x)
					return 0, false
				}
				n, err := strconv.Atoi(parts[0])
				if err != nil {
					logger.Error("failed to parse WAP value", "type", t, "error", err)
				}
				return n, err == nil

			}

			c, err := strconv.Atoi(fields[5])
			if err != nil {
				logger.Error("failed to parse WAP value", "type", "channel", "error", err)
				continue
			}
			f, ok1 := atoiFirst(fields[6], "frequency")
			r, ok2 := atoiFirst(fields[7], "rate")
			b, ok3 := atoiFirst(fields[8], "bandwidth")
			si, ok4 := atoiFirst(fields[9], "signal")
			if !ok1 || !ok2 || !ok3 || !ok4 {
				continue
			}

			var sec string
			if fields[11] == "" {
				sec = "Open"
			} else {
				sec = fields[11]
			}

			result := NMCLIOutput{
				SSID:      fields[1],
				SSID_Hex:  fields[2],
				BSSID:     strings.ReplaceAll(fields[3], "\x00", ":"),
				Mode:      fields[4],
				Chan:      c,
				Freq:      f,
				Rate:      r,
				Bandwidth: b,
				Signal:    si,
				Security:  sec,
				WPAFlags:  fields[12],
				RSNFlags:  fields[13],
				Device:    fields[14],
				Active:    fields[15],
				InUse:     fields[16] == "*",
				DBusPath:  fields[17],
			}
			logger.Debug("result parsed", "result", result)
			select {
			case out <- result:
				logger.Debug("sending to out")
			case <-ctx.Done():
				return nil
			}
		}
	}
}

// TODO: make this generic and use a strategy pattern to split based on sec protocl
func connectToPublicWAPs(idle time.Duration, ctx context.Context, logger *slog.Logger, db *sql.DB) error {
	ticker := time.NewTicker(idle)
	joinPublicSQL := `
	SELECT ssid, bssid, updated_at FROM waps
	WHERE security = "Open"
	AND in_use = 0
	AND visible = 1
	ORDER BY updated_at DESC
	-- ORDER BY signal DESC
	`
	connect := func(SSID, BSSID string) (string, error) {
		logger.Debug("starting scan")
		name := SSID
		if name == "" {
			name = BSSID
		}
		raw, err := exec.CommandContext(ctx, "nmcli", "dev", "wifi", "connect", name, "ifname", "wlan0").Output()
		if err != nil {
			if ctx.Err() != nil {
				return "", nil
			}
			logger.Error("failed to exec nmcli", "error", err)
			return "", err
		}
		outString := string(raw)
		logger.Debug("outstring received", "outString", outString)
		return outString, nil

	}
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			logger.Info("closing filter gracefully")
			return ctx.Err()
		case <-ticker.C:
			rows, err := db.Query(joinPublicSQL)
			if err != nil {
				logger.Error("failed to pull rows", "error", err)
			}
			defer rows.Close()
			for rows.Next() {
				var (
					SSID            string
					BSSID           string
					updatedUnixTime int64
				)
				if err := rows.Scan(&SSID, &BSSID, &updatedUnixTime); err != nil {
					logger.Error("failed to parse row", "error", err)
				}
				if SSID == "" {
					continue
				}
				lastSeen := time.Unix(updatedUnixTime, 0)
				logger.Info("Available Public WAP", "SSID", SSID, "MAC", BSSID, "last_seen(local)", lastSeen, "last_seen(UTC)", lastSeen.UTC())
				logger.Info("attempting to connect")
				result, err := connect(SSID, BSSID)
				if err != nil {
					logger.Error("i failed in some sorta way idfk", "cmd result", result, "error", err)
					continue
				}
				logger.Info("holy shit i actually connected to the WAP")
				// TODO: attempt to phone home
			}
		}
	}
}

func logWAPs(in chan DBChange, ctx context.Context, logger *slog.Logger) error {
	logger.Debug("starting filter")
	for {
		select {
		case <-ctx.Done():
			logger.Info("closing filter gracefully")
			return ctx.Err()
		case change, ok := <-in:
			if !ok {
				return nil
			}
			if !change.Upserted {
				continue
			}
			wap := change.Row
			logger.Debug("pulling wap from input", "wap", wap)
			switch wap.Security {
			case "Open":
				logger.Info("Public WAP spotted", "SSID", wap.SSID, "MAC", wap.BSSID, "mode", wap.Mode)
			case "WPA":
				fallthrough
			case "WPA2":
				fallthrough
			case "WPA3":
				fallthrough
			case "WEP":
				logger.Info("Protected WAP spotted", "security", wap.Security, "SSID", wap.SSID, "MAC", wap.BSSID, "mode", wap.Mode)
			default:
				logger.Info("Unknown WAP spotted", "security", wap.Security, "SSID", wap.SSID, "MAC", wap.BSSID, "mode", wap.Mode)
			}
		}
	}
}

func initDB(db *sql.DB) error {
	_, err := db.Exec(`
		PRAGMA journal_mode=WAL;
		PRAGMA synchronous=NORMAL;
		PRAGMA busy_timeout=2000;
		PRAGMA foreign_keys = ON;
		CREATE TABLE IF NOT EXISTS waps(
		    id INTEGER PRIMARY KEY AUTOINCREMENT,
		    ssid TEXT,
		    ssid_hex TEXT,
		    bssid TEXT UNIQUE NOT NULL,
		    mode TEXT,
		    chan INTEGER,
		    freq INTEGER,
		    rate INTEGER,
		    bandwidth INTEGER,
		    signal INTEGER,
		    security TEXT,
		    wpa_flags TEXT,
		    rsn_flags TEXT,
		    device TEXT,
		    active TEXT,
		    in_use INTEGER,
		    dbus_path TEXT,
		    password TEXT,
		    successfully_connected INTEGER,
		    created_at INTEGER,
		    updated_at INTEGER,
		    visible INTEGER
		);
		CREATE INDEX IF NOT EXISTS idx_waps_ssid ON waps(ssid);
		CREATE TABLE IF NOT EXISTS passwords(
		    id INTEGER PRIMARY KEY AUTOINCREMENT,
		    wap_id INTEGER NOT NULL,
		    password TEXT,
		    FOREIGN KEY (wap_id) REFERENCES waps(id) ON DELETE CASCADE
		);
		`)
	return err
}

func writeWAPs(in <-chan NMCLIOutput, out chan<- DBChange, db *sql.DB, batchSize int, flushEvery time.Duration, ctx context.Context, logger *slog.Logger) error {
	logger.Debug("starting db writer")

	ticker := time.NewTicker(flushEvery)
	defer ticker.Stop()

	type pending struct{ row NMCLIOutput }
	batch := make([]pending, 0, batchSize)

	upsertSQL := `
	INSERT INTO waps
	(ssid, ssid_hex, bssid, mode, chan, freq, rate,
	bandwidth, signal, security, wpa_flags, rsn_flags,
	device, active, in_use, dbus_path, created_at, updated_at, visible)
	VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 1)
	ON CONFLICT(bssid) DO UPDATE SET
	  ssid=excluded.ssid,
	  ssid_hex=excluded.ssid_hex,
	  mode=excluded.mode,
	  chan=excluded.chan,
	  freq=excluded.freq,
	  rate=excluded.rate,
	  bandwidth=excluded.bandwidth,
	  signal=excluded.signal,
	  security=excluded.security,
	  wpa_flags=excluded.wpa_flags,
	  rsn_flags=excluded.rsn_flags,
	  device=excluded.device,
	  active=excluded.active,
	  in_use=excluded.in_use,
	  dbus_path=excluded.dbus_path,
	  updated_at=excluded.updated_at,
	  visible=1
	RETURNING (created_at = updated_at) AS was_insert
	`
	boolToInt := func(b bool) int {
		if b {
			return 1
		}
		return 0
	}

	flush := func() {
		logger.Debug("writing to db!")
		if len(batch) == 0 {
			return
		}
		tx, err := db.Begin()
		if err != nil {
			logger.Error("begin tx failed", "error", err)
			batch = batch[:0]
			return
		}
		stmt, err := tx.Prepare(upsertSQL)
		if err != nil {
			logger.Error("prepare stmt failed", "error", err)
		}

		now := time.Now().Unix()
		for _, p := range batch {
			it := p.row
			var wasInsert int64
			row := stmt.QueryRow(
				it.SSID, it.SSID_Hex, it.BSSID, it.Mode,
				it.Chan, it.Freq, it.Rate, it.Bandwidth, it.Signal,
				it.Security, it.WPAFlags, it.RSNFlags,
				it.Device, it.Active, boolToInt(it.InUse),
				it.DBusPath, now, now,
			)
			if err := row.Scan(&wasInsert); err != nil {
				logger.Error("upsert failed", "ssid", it.SSID, "error", err)
				continue
			}
			change := DBChange{Row: it, Upserted: wasInsert == 1}
			select {
			case out <- change:
			case <-ctx.Done():
				_ = stmt.Close()
				_ = tx.Commit()
				return
			}
		}

		_ = stmt.Close()
		if err := tx.Commit(); err != nil {
			_ = tx.Rollback()
			logger.Error("commit failed", "error", err)
		}
		batch = batch[:0]
	}

	for {
		select {
		case <-ctx.Done():
			flush()
			logger.Debug("closing db writer gracefully")
			return nil
		case it, ok := <-in:
			if !ok {
				flush()
				return nil
			}
			batch = append(batch, pending{row: it})
			if len(batch) >= batchSize {
				flush()
			}
		case <-ticker.C:
			flush()
		}
	}
}
