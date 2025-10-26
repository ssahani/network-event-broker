// SPDX-License-Identifier: Apache-2.0
// Copyright 2023 VMware, Inc.

package system

import (
	"fmt"
	"syscall"

	"github.com/rs/zerolog/log"
	"github.com/syndtr/gocapability/capability"
	"golang.org/x/sys/unix"
)

// ApplyCapability sets necessary Linux capabilities for a process.
func ApplyCapability(cred *syscall.Credential) error {
	if cred == nil {
		log.Error().Msg("Credential cannot be nil")
		return fmt.Errorf("credential cannot be nil")
	}

	caps, err := capability.NewPid2(0)
	if err != nil {
		log.Error().Err(err).Msg("Failed to initialize capabilities for PID 0")
		return fmt.Errorf("failed to initialize capabilities: %w", err)
	}

	// Define capability types to manage.
	const allCapabilityTypes = capability.CAPS | capability.BOUNDS | capability.AMBS

	// Clear all existing capabilities.
	if err := caps.Clear(allCapabilityTypes); err != nil {
		log.Error().Err(err).Msg("Failed to clear capabilities")
		return fmt.Errorf("failed to clear capabilities: %w", err)
	}

	// Set CAP_NET_ADMIN and CAP_SYS_ADMIN for required capability sets.
	for _, capType := range []capability.CapType{capability.BOUNDS, capability.PERMITTED, capability.INHERITABLE, capability.EFFECTIVE} {
		if err := caps.Set(capType, capability.CAP_NET_ADMIN, capability.CAP_SYS_ADMIN); err != nil {
			log.Error().Err(err).Str("cap_type", capType.String()).Msg("Failed to set capabilities")
			return fmt.Errorf("failed to set %s capabilities: %w", capType, err)
		}
	}

	// Explicitly clear ambient capabilities.
	if err := caps.Clear(capability.AMBIENT); err != nil {
		log.Warn().Err(err).Msg("Failed to clear ambient capabilities")
		// Continue as this may not be critical.
	}

	// Apply the capability changes.
	if err := caps.Apply(allCapabilityTypes); err != nil {
		log.Error().Err(err).Msg("Failed to apply capabilities")
		return fmt.Errorf("failed to apply capabilities: %w", err)
	}

	log.Debug().Uint32("uid", cred.Uid).Msg("Successfully applied CAP_NET_ADMIN and CAP_SYS_ADMIN capabilities")
	return nil
}

// EnableKeepCapability enables the PR_SET_KEEPCAPS flag to retain capabilities across privilege changes.
func EnableKeepCapability() error {
	if err := unix.Prctl(unix.PR_SET_KEEPCAPS, 1, 0, 0, 0); err != nil {
		log.Error().Err(err).Msg("Failed to enable PR_SET_KEEPCAPS")
		return fmt.Errorf("failed to enable PR_SET_KEEPCAPS: %w", err)
	}

	log.Debug().Msg("Successfully enabled PR_SET_KEEPCAPS")
	return nil
}

// DisableKeepCapability disables the PR_SET_KEEPCAPS flag.
func DisableKeepCapability() error {
	if err := unix.Prctl(unix.PR_SET_KEEPCAPS, 0, 0, 0, 0); err != nil {
		log.Error().Err(err).Msg("Failed to disable PR_SET_KEEPCAPS")
		return fmt.Errorf("failed to disable PR_SET_KEEPCAPS: %w", err)
	}

	log.Debug().Msg("Successfully disabled PR_SET_KEEPCAPS")
	return nil
}
