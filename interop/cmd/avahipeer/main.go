// Copyright 2026 Abhinav Gautam
// SPDX-License-Identifier: Apache-2.0

// Command avahipeer runs github.com/cB-Sigma/mdns inside the Linux
// containers of the Avahi interop test (../../avahi_test.go) and prints
// what it found or did as JSON lines:
//
//	avahipeer [-out file] browse <type> <wait> [both|oneshot|multicast]
//	avahipeer [-out file] types <wait>
//	avahipeer [-out file] announce <instance> <host> <type> <port> <duration> [subtype]
//	avahipeer [-out file] announce-many <prefix> <n> <host> <type> <port> <duration>
//	avahipeer [-out file] reflect <duration>
//
// It uses every multicast-capable interface of the container and the real
// mDNS port, next to the container's avahi-daemon.
package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strconv"
	"time"

	"github.com/cB-Sigma/mdns"
)

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, "avahipeer:", err)
		os.Exit(1)
	}
}

type found struct {
	Instance string            `json:"instance"`
	Host     string            `json:"host"`
	Port     int               `json:"port"`
	TXT      map[string]string `json:"txt"`
	IPs      []string          `json:"ips"`
}

// out is where the JSON lines go: standard output, or the file given with
// -out (for runs started detached with docker exec -d).
var out io.Writer = os.Stdout

func emit(v any) {
	b, _ := json.Marshal(v)
	fmt.Fprintln(out, string(b))
}

func run(args []string) error {
	if len(args) >= 2 && args[0] == "-out" {
		f, err := os.Create(args[1])
		if err != nil {
			return err
		}
		defer f.Close()
		out, args = f, args[2:]
	}
	if len(args) == 0 {
		return fmt.Errorf("usage: browse | types | announce")
	}
	ctx := context.Background()
	switch args[0] {
	case "browse":
		if len(args) < 3 {
			return fmt.Errorf("browse <type> <wait> [mode]")
		}
		wait, err := time.ParseDuration(args[2])
		if err != nil {
			return err
		}
		opts := mdns.Options{Wait: wait}
		if len(args) > 3 {
			switch args[3] {
			case "oneshot":
				opts.Mode = mdns.BrowseOneShot
			case "multicast":
				opts.Mode = mdns.BrowseMulticast
			}
		}
		list, err := mdns.Browse(ctx, args[1], opts)
		if err != nil {
			return err
		}
		out := []found{}
		for _, s := range list {
			f := found{Instance: s.Instance, Host: s.Host, Port: s.Port, TXT: s.TXT}
			for _, ip := range s.IPs {
				f.IPs = append(f.IPs, ip.String())
			}
			out = append(out, f)
		}
		emit(out)
	case "types":
		if len(args) < 2 {
			return fmt.Errorf("types <wait>")
		}
		wait, err := time.ParseDuration(args[1])
		if err != nil {
			return err
		}
		types, err := mdns.BrowseServiceTypes(ctx, mdns.Options{Wait: wait})
		if err != nil {
			return err
		}
		emit(types)
	case "announce":
		if len(args) < 6 {
			return fmt.Errorf("announce <instance> <host> <type> <port> <duration> [subtype]")
		}
		port, err := strconv.Atoi(args[4])
		if err != nil {
			return err
		}
		d, err := time.ParseDuration(args[5])
		if err != nil {
			return err
		}
		s := mdns.Service{Instance: args[1], Host: args[2], Port: port, TXT: map[string]string{"peer": "sigma"}}
		if len(args) > 6 {
			s.Subtypes = []string{args[6]}
		}
		opts := mdns.Options{Rename: mdns.RenameInstance, OnConflict: func(e mdns.ConflictEvent) {
			emit(map[string]string{"event": "conflict-" + e.Kind.String(), "instance": e.Service.Instance, "previous": e.Previous.Instance})
		}}
		a, err := mdns.Announce(ctx, s, args[3], opts)
		if err != nil {
			return err
		}
		emit(map[string]string{"event": "announced", "instance": a.Service().Instance})
		time.Sleep(d)
		emit(map[string]string{"event": "closing", "instance": a.Service().Instance})
		return a.Close()
	case "reflect":
		// reflect <duration>: an mDNS reflector on every interface.
		if len(args) < 2 {
			return fmt.Errorf("reflect <duration>")
		}
		d, err := time.ParseDuration(args[1])
		if err != nil {
			return err
		}
		r, err := mdns.Reflect(ctx, mdns.Options{})
		if err != nil {
			return err
		}
		emit(map[string]any{"event": "reflecting"})
		time.Sleep(d)
		emit(map[string]any{"event": "reflected", "count": r.Reflected()})
		return r.Close()
	case "announce-many":
		// announce-many <prefix> <n> <host> <type> <port> <duration>: n
		// instances "<prefix> <i>" on one host, for responses that need
		// more than one packet.
		if len(args) < 7 {
			return fmt.Errorf("announce-many <prefix> <n> <host> <type> <port> <duration>")
		}
		n, err := strconv.Atoi(args[2])
		if err != nil {
			return err
		}
		port, err := strconv.Atoi(args[5])
		if err != nil {
			return err
		}
		d, err := time.ParseDuration(args[6])
		if err != nil {
			return err
		}
		var all []*mdns.Announcer
		for i := 0; i < n; i++ {
			s := mdns.Service{Instance: fmt.Sprintf("%s %d", args[1], i), Host: args[3], Port: port, TXT: map[string]string{"peer": "sigma"}}
			a, err := mdns.Announce(ctx, s, args[4], mdns.Options{Rename: mdns.RenameInstance})
			if err != nil {
				return err
			}
			all = append(all, a)
		}
		emit(map[string]any{"event": "announced", "count": len(all)})
		time.Sleep(d)
		for _, a := range all {
			_ = a.Close()
		}
	default:
		return fmt.Errorf("unknown command %q", args[0])
	}
	return nil
}
