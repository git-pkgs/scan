package engine

import "errors"

var (
	ErrInvalid        = errors.New("invalid argument")
	ErrScanTerminated = errors.New("scan terminated")
	ErrScratchInUse   = errors.New("scratch is already in use")
)
