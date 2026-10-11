// Copyright 2026 Abhinav Gautam
// SPDX-License-Identifier: Apache-2.0

package mdns_test

import (
	"context"
	"fmt"
	"time"

	"github.com/cB-Sigma/mdns"
)

// Browse finds the instances of a type: by default it queries one-shot
// from an ephemeral port and from the mDNS port at once.
func ExampleBrowse() {
	ctx := context.Background()
	found, err := mdns.Browse(ctx, "_hue._tcp", mdns.Options{Wait: 3 * time.Second})
	if err != nil {
		return
	}
	for _, s := range found {
		fmt.Println(s.Instance, s.Addr(), s.TXT["bridgeid"])
	}
}

// Announce advertises a service with a subtype and renames it if the name
// is taken; UpdateTXT changes its metadata without probing again.
func ExampleAnnounce() {
	ctx := context.Background()
	a, err := mdns.Announce(ctx, mdns.Service{Instance: "Site gateway", Host: "gateway", Port: 8443,
		TXT: map[string]string{"version": "1"}, Subtypes: []string{"_vtn"}}, "_openadr3._tcp",
		mdns.Options{Rename: mdns.RenameInstance})
	if err != nil {
		return
	}
	defer a.Close()
	_ = a.UpdateTXT(map[string]string{"version": "2"})
}

// RenameInstance numbers the instance name after a conflict and keeps the
// host name.
func ExampleRenameInstance() {
	s := mdns.Service{Instance: "Site gateway", Host: "gateway", Port: 8443}
	s = mdns.RenameInstance(s, 1)
	fmt.Println(s.Instance)
	fmt.Println(mdns.RenameInstance(s, 2).Instance)
	fmt.Println(s.Addr())
	// Output:
	// Site gateway (2)
	// Site gateway (3)
	// gateway:8443
}

// Watch follows instances as they come, change and go.
func ExampleWatch() {
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	w, err := mdns.Watch(ctx, []string{"_ewelink._tcp", "_shelly._tcp"}, mdns.Options{}, func(e mdns.Event) {
		fmt.Println(e.Kind, e.Type, e.Service.Instance, e.Service.TXT["seq"])
	})
	if err != nil {
		return
	}
	defer w.Close()
	<-w.Settled()
	fmt.Println(len(w.Services("_ewelink._tcp")), "DIY devices so far")
	<-ctx.Done()
}
