//go:build yubikey

package pcsc

import (
	"errors"
	"fmt"

	"github.com/ebfe/scard"

	"alice/internal/vconsole/sign/openpgp"
)

// Readers lists the names of the connected PC/SC readers; none connected is an empty list.
func Readers() ([]string, error) {
	sc, err := scard.EstablishContext()
	if err != nil {
		return nil, mapErr("establish context", err)
	}
	defer func() { _ = sc.Release() }()
	return listReaders(sc)
}

func listReaders(sc *scard.Context) ([]string, error) {
	names, err := sc.ListReaders()
	if errors.Is(err, scard.ErrNoReadersAvailable) {
		return []string{}, nil
	}
	if err != nil {
		return nil, mapErr("list readers", err)
	}
	return names, nil
}

// Connect opens the reader named exactly, or when name is "" the only reader whose name contains
// "yubi" (case-insensitive); more than one candidate is an error that lists the names.
func Connect(name string) (openpgp.Card, error) {
	sc, err := scard.EstablishContext()
	if err != nil {
		return nil, mapErr("establish context", err)
	}
	names, err := listReaders(sc)
	if err != nil {
		_ = sc.Release()
		return nil, err
	}
	reader, err := pick(names, name)
	if err != nil {
		_ = sc.Release()
		return nil, err
	}
	// Shared, not exclusive: an exclusive hold would lock scdaemon out until we exit, and a
	// crash would leave the operator guessing. The signing sequence (VERIFY then PSO) is short.
	card, err := sc.Connect(reader, scard.ShareShared, scard.ProtocolAny)
	if err != nil {
		_ = sc.Release()
		return nil, mapErr("connect", err)
	}
	// scard's Transmit panics on any other protocol: refuse such a card here instead.
	if p := card.ActiveProtocol(); p != scard.ProtocolT0 && p != scard.ProtocolT1 {
		_ = card.Disconnect(scard.LeaveCard)
		_ = sc.Release()
		return nil, fmt.Errorf("pcsc: connect: the card speaks no supported protocol (%d)", p)
	}
	return newConn(&scardRaw{ctx: sc, card: card}, func() { _ = sc.Cancel() },
		func(err error) error { return mapErr("transmit", err) }), nil
}

// scardRaw is the real handle behind a conn.
type scardRaw struct {
	ctx  *scard.Context
	card *scard.Card
}

func (r *scardRaw) Transmit(apdu []byte) ([]byte, error) { return r.card.Transmit(apdu) }

// Disconnect resets the card on the way out, so that the verified signing PIN does not stay
// valid for whatever program talks to the card next, then releases the context.
func (r *scardRaw) Disconnect() error {
	err := r.card.Disconnect(scard.ResetCard)
	if rerr := r.ctx.Release(); err == nil {
		err = rerr
	}
	return err
}

// mapErr turns a PC/SC status into one of the readable errors of this package. The text names
// the operation and the condition only; scard errors carry a status code, never command bytes.
func mapErr(op string, err error) error {
	if err == nil {
		return nil
	}
	var code scard.Error
	if !errors.As(err, &code) {
		return fmt.Errorf("pcsc: %s: %w", op, err)
	}
	var readable error
	switch code {
	case scard.ErrNoService, scard.ErrServiceStopped:
		readable = ErrNoService
	case scard.ErrNoReadersAvailable:
		readable = ErrNoReaders
	case scard.ErrNoSmartcard:
		readable = ErrNoCard
	case scard.ErrRemovedCard, scard.ErrResetCard:
		readable = ErrCardRemoved
	case scard.ErrReaderUnavailable, scard.ErrUnknownReader:
		readable = ErrReaderUnavailable
	case scard.ErrSharingViolation:
		readable = ErrSharingViolation
	case scard.ErrTimeout, scard.ErrWaitedTooLong, scard.ErrUnresponsiveCard:
		readable = ErrTimeout
	default:
		return fmt.Errorf("pcsc: %s: %w", op, err)
	}
	return fmt.Errorf("%w (during %s)", readable, op)
}
