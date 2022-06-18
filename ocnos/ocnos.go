package ocnos

import (
	"github.com/scrapli/scrapligo/driver/base"
	"github.com/scrapli/scrapligo/driver/network"
)

// NewOcNOSDriver global var allows to rewrite the driver initialization function for patched variant in testing
var NewOcNOSDriver = newOcNOSDriver

// newOcNOSDriver returns a driver setup for operation with IPInfusion OcNOS devices.
func newOcNOSDriver(
	host string,
	options ...base.Option,
) (*network.Driver, error) {
	defaultPrivilegeLevels := map[string]*base.PrivilegeLevel{
		// linux shell that ocnos boots in by default
		"linux": {
			Pattern:        `(?im)^\S+@\S+\:\S+[\#\?]\s*$`,
			Name:           "linux",
			PreviousPriv:   "",
			Deescalate:     "",
			Escalate:       "",
			EscalateAuth:   false,
			EscalatePrompt: ``,
		},
		// ocnos shell mode
		"exec": {
			Pattern:        `(?im)^[\w.\-@/:]{1,63}>\s*$`,
			Name:           "exec",
			PreviousPriv:   "linux",
			Deescalate:     "logout",
			Escalate:       "cmlsh",
			EscalateAuth:   false,
			EscalatePrompt: ``,
		},
		"privilege_exec": {
			Pattern:        `(?im)^[\w.\-@/:]{1,63}#\s*$`,
			Name:           "privilege_exec",
			PreviousPriv:   "exec",
			Deescalate:     "disable",
			Escalate:       "enable",
			EscalateAuth:   false,
			EscalatePrompt: ``,
		},
		"configuration": {
			Pattern:        `(?im)^[\w.\-@/:]{1,63}\([\w.\-@/:+]{0,32}\)#\s*$`,
			Name:           "configuration",
			PreviousPriv:   "privilege_exec",
			Deescalate:     "end",
			Escalate:       "configure terminal",
			EscalateAuth:   false,
			EscalatePrompt: "",
		},
	}

	defaultFailedWhenContains := []string{
		"% Ambiguous command",
		"% Incomplete command",
		"% Invalid input detected",
		"% Unknown command",
	}

	const defaultDefaultDesiredPriv = "privilege_exec"

	d, err := network.NewNetworkDriver(
		host,
		defaultPrivilegeLevels,
		defaultDefaultDesiredPriv,
		defaultFailedWhenContains,
		OcNOSOnOpen,
		OcNOSOnClose,
		options...)

	if err != nil {
		return nil, err
	}

	return d, nil
}

// OcNOSOnOpen is a default on open callable.
func OcNOSOnOpen(d *network.Driver) error {
	err := d.AcquirePriv(d.DefaultDesiredPriv)
	if err != nil {
		return err
	}

	_, err = d.SendCommand("terminal length 0", nil)
	if err != nil {
		return err
	}

	_, err = d.SendCommand("terminal width 511", nil)
	if err != nil {
		return err
	}

	return nil
}

// OcNOSOnClose is a default on close callable.
func OcNOSOnClose(d *network.Driver) error {
	err := d.AcquirePriv(d.DefaultDesiredPriv)
	if err != nil {
		return err
	}

	err = d.Channel.Write([]byte("exit"), false)
	if err != nil {
		return err
	}

	err = d.Channel.SendReturn()
	if err != nil {
		return err
	}

	return nil
}

// NewPatchedOcNOSDriver returns a new driver and allows to rewrite the default function NewSRLinuxDriver
func NewPatchedOcNOSDriver(
	host string,
	options ...base.Option,
) (*network.Driver, error) {
	return newOcNOSDriver(
		host,
		options...,
	)
}
