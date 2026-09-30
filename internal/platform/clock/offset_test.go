package clock_test

import (
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"

	"alice/internal/platform/clock"
)

func TestOffsetShiftsNowOnly(t *testing.T) {
	start := time.Date(2026, 9, 30, 10, 0, 0, 0, time.UTC)
	base := clock.NewFake(start)
	o := clock.NewOffset(base)
	var _ clock.Clock = o

	assert.Equal(t, start, o.Now())
	o.Advance(31 * time.Minute)
	assert.Equal(t, start.Add(31*time.Minute), o.Now())
	o.Advance(-time.Minute)
	assert.Equal(t, start.Add(30*time.Minute), o.Now())

	ch := o.After(time.Second)
	base.Advance(time.Second)
	select {
	case <-ch:
	default:
		t.Fatal("After must fire on the base clock")
	}
	assert.Equal(t, start.Add(30*time.Minute+time.Second), o.Now())

	o.Reset()
	assert.Equal(t, start.Add(time.Second), o.Now())
}

func TestOffsetIsSafeForConcurrentUse(t *testing.T) {
	o := clock.NewOffset(clock.NewFake(time.Unix(0, 0)))
	var wg sync.WaitGroup
	for range 50 {
		wg.Add(2)
		go func() { defer wg.Done(); o.Advance(time.Second) }()
		go func() { defer wg.Done(); _ = o.Now() }()
	}
	wg.Wait()
	assert.Equal(t, time.Unix(50, 0).UTC(), o.Now())
}
