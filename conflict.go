// Copyright 2026 Abhinav Gautam
// SPDX-License-Identifier: Apache-2.0

package mdns

import (
	"fmt"
	"strings"
	"time"
)

// ConflictKind says what an announcer did about a name conflict.
type ConflictKind int

// The conflict kinds, in the order they can happen.
const (
	// ConflictSeen: after probing, another responder answered with other
	// data for our instance or host name; the announcer stops answering
	// for the names and probes them again (RFC 6762 clause 9).
	ConflictSeen ConflictKind = iota + 1
	// ConflictKept: probing again found no other owner (the conflicting
	// record was stale); the names are announced again.
	ConflictKept
	// ConflictRenamed: the name is taken; the announcer now announces
	// Service, renamed through Options.Rename, instead of Previous.
	ConflictRenamed
	// ConflictWithdrawn: the name is taken and no rename was possible (no
	// Options.Rename, or MaxRenames reached); the announcer has stopped
	// answering and Err returns Err.
	ConflictWithdrawn
)

func (k ConflictKind) String() string {
	switch k {
	case ConflictSeen:
		return "seen"
	case ConflictKept:
		return "kept"
	case ConflictRenamed:
		return "renamed"
	case ConflictWithdrawn:
		return "withdrawn"
	}
	return "unknown"
}

// ConflictEvent is one step of an announcer's conflict handling, given to
// Options.OnConflict.
type ConflictEvent struct {
	Kind ConflictKind
	// Service is the service as announced after this step.
	Service Service
	// Previous is the service given up, for ConflictRenamed.
	Previous Service
	// Err wraps ErrConflict, for ConflictWithdrawn.
	Err error
}

// conflictWindow and conflictLimit: after conflictLimit conflicts within
// conflictWindow a responder waits conflictPause before probing again
// (RFC 6762 clause 8.1).
var (
	conflictWindow = 10 * time.Second
	conflictLimit  = 15
	conflictPause  = 5 * time.Second
)

func (a *Announcer) emit(e ConflictEvent) {
	if a.opts.OnConflict != nil {
		a.opts.OnConflict(e)
	}
}

// conflictSeen starts handling a conflict noticed after probing, unless
// one is already being handled.
func (a *Announcer) conflictSeen() {
	if a.withdrawn.Load() || a.closed() || !a.reprobing.CompareAndSwap(false, true) {
		return
	}
	// Stop answering for the names at once (RFC 6762 clause 9).
	a.conflict.Store(false)
	a.lostTie.Store(false)
	a.probing.Store(true)
	a.wg.Add(1)
	go a.reprobe()
}

// reprobe probes the names again; when they are taken it renames and
// probes the new names, or withdraws.
func (a *Announcer) reprobe() {
	defer a.wg.Done()
	defer a.reprobing.Store(false)
	a.emit(ConflictEvent{Kind: ConflictSeen, Service: a.Service()})
	var previous *Service
	for attempt := 1; ; attempt++ {
		if wait := a.conflictBackoff(time.Now()); wait > 0 {
			t := time.NewTimer(wait)
			select {
			case <-a.done:
				t.Stop()
				return
			case <-t.C:
			}
		}
		a.conflict.Store(false)
		a.lostTie.Store(false)
		a.probing.Store(true)
		err := a.probe(a.ctx)
		if a.closed() {
			return
		}
		if err == nil {
			a.probing.Store(false)
			a.wg.Add(1)
			go a.announceLoop(announceAt)
			if previous != nil {
				a.emit(ConflictEvent{Kind: ConflictRenamed, Service: a.Service(), Previous: *previous})
			} else {
				a.emit(ConflictEvent{Kind: ConflictKept, Service: a.Service()})
			}
			return
		}
		a.noteConflict(time.Now())
		cur := a.Service()
		if a.opts.Rename == nil || attempt > MaxRenames {
			a.withdraw(fmt.Errorf("%w: %s or %s", ErrConflict, a.r().instName, a.r().hostName))
			return
		}
		if err := a.rename(cur); err != nil {
			a.withdraw(fmt.Errorf("%w: rename: %v", ErrConflict, err))
			return
		}
		if previous == nil {
			previous = &cur
		}
	}
}

// rename asks Options.Rename for the next name, numbering on from the
// renames so far, skipping a result that keeps both names, and switches
// the responder to it.
func (a *Announcer) rename(cur Service) error {
	r := a.r()
	for range MaxRenames {
		a.svcMu.Lock()
		a.renames++
		n := a.renames
		a.svcMu.Unlock()
		next := a.opts.Rename(cur, n)
		if strings.EqualFold(next.Instance, cur.Instance) && strings.EqualFold(hostLabel(next.Host), hostLabel(cur.Host)) {
			continue
		}
		next.TXT = cur.TXT
		nr, err := r.renamed(next, a.service)
		if err != nil {
			return err
		}
		a.rp.Store(nr)
		a.svcMu.Lock()
		a.svc = cloneService(next)
		a.svcMu.Unlock()
		return nil
	}
	return fmt.Errorf("Rename kept the name %q", cur.Instance)
}

// withdraw gives the names up: no more answers, announcements or goodbyes.
func (a *Announcer) withdraw(err error) {
	a.errMu.Lock()
	a.err = err
	a.errMu.Unlock()
	a.withdrawn.Store(true)
	a.probing.Store(false)
	a.emit(ConflictEvent{Kind: ConflictWithdrawn, Service: a.Service(), Err: err})
}

func (a *Announcer) noteConflict(now time.Time) {
	a.svcMu.Lock()
	defer a.svcMu.Unlock()
	a.conflictAt = append(a.conflictAt, now)
}

// conflictBackoff is how long to wait before the next probe: conflictPause
// after conflictLimit conflicts within conflictWindow, otherwise nothing.
func (a *Announcer) conflictBackoff(now time.Time) time.Duration {
	a.svcMu.Lock()
	defer a.svcMu.Unlock()
	var recent []time.Time
	for _, t := range a.conflictAt {
		if now.Sub(t) < conflictWindow {
			recent = append(recent, t)
		}
	}
	a.conflictAt = recent
	if len(recent) >= conflictLimit {
		return conflictPause
	}
	return 0
}
