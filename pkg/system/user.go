// SPDX-License-Identifier: Apache-2.0
// Copyright 2023 VMware, Inc.

package system

import (
	"fmt"
	"os/user"
	"strconv"
	"syscall"

	"github.com/rs/zerolog/log"
)

// GetUserCredentials retrieves the credentials for a specified user or the current user.
func GetUserCredentials(username string) (*syscall.Credential, error) {
	var u *user.User
	var err error

	if username == "" {
		u, err = user.Current()
		log.Debug().Msg("Looking up credentials for current user")
	} else {
		u, err = user.Lookup(username)
		log.Debug().Str("username", username).Msg("Looking up user credentials")
	}
	if err != nil {
		log.Error().Str("username", username).Err(err).Msg("Failed to lookup user")
		return nil, fmt.Errorf("failed to lookup user %q: %w", username, err)
	}

	uid, err := strconv.ParseUint(u.Uid, 10, 32)
	if err != nil {
		log.Error().Str("uid", u.Uid).Err(err).Msg("Failed to parse UID")
		return nil, fmt.Errorf("failed to parse UID %s for user %q: %w", u.Uid, username, err)
	}

	gid, err := strconv.ParseUint(u.Gid, 10, 32)
	if err != nil {
		log.Error().Str("gid", u.Gid).Err(err).Msg("Failed to parse GID")
		return nil, fmt.Errorf("failed to parse GID %s for user %q: %w", u.Gid, username, err)
	}

	cred := &syscall.Credential{
		Uid: uint32(uid),
		Gid: uint32(gid),
	}
	log.Debug().Str("username", u.Username).Uint32("uid", cred.Uid).Uint32("gid", cred.Gid).Msg("Successfully retrieved user credentials")
	return cred, nil
}

// SwitchUser switches the process to run as the specified user credentials.
func SwitchUser(cred *syscall.Credential) error {
	if cred == nil {
		log.Error().Msg("Credential cannot be nil")
		return fmt.Errorf("credential cannot be nil")
	}

	// Set group ID first to ensure proper permissions.
	if _, _, errno := syscall.RawSyscall(syscall.SYS_SETGID, uintptr(cred.Gid), 0, 0); errno != 0 {
		err := syscall.Errno(errno)
		log.Error().Uint32("gid", cred.Gid).Err(err).Msg("Failed to set GID")
		return fmt.Errorf("failed to set GID %d: %w", cred.Gid, err)
	}

	// Set user ID after GID to avoid permission issues.
	if _, _, errno := syscall.RawSyscall(syscall.SYS_SETUID, uintptr(cred.Uid), 0, 0); errno != 0 {
		err := syscall.Errno(errno)
		log.Error().Uint32("uid", cred.Uid).Err(err).Msg("Failed to set UID")
		return fmt.Errorf("failed to set UID %d: %w", cred.Uid, err)
	}

	log.Debug().Uint32("uid", cred.Uid).Uint32("gid", cred.Gid).Msg("Successfully switched user credentials")
	return nil
}

// GetUserCredentialsByUid retrieves user information for a given UID.
func GetUserCredentialsByUid(uid uint32) (*user.User, error) {
	uidStr := strconv.FormatUint(uint64(uid), 10)
	u, err := user.LookupId(uidStr)
	if err != nil {
		log.Error().Uint32("uid", uid).Err(err).Msg("Failed to lookup user by UID")
		return nil, fmt.Errorf("failed to lookup user by UID %d: %w", uid, err)
	}

	log.Debug().Uint32("uid", uid).Str("username", u.Username).Msg("Successfully retrieved user by UID")
	return u, nil
}

// GetGroupCredentials retrieves group information for a specified group name.
func GetGroupCredentials(groupName string) (*user.Group, error) {
	if groupName == "" {
		log.Error().Msg("Group name cannot be empty")
		return nil, fmt.Errorf("group name cannot be empty")
	}

	group, err := user.LookupGroup(groupName)
	if err != nil {
		log.Error().Str("group", groupName).Err(err).Msg("Failed to lookup group")
		return nil, fmt.Errorf("failed to lookup group %q: %w", groupName, err)
	}

	log.Debug().Str("group", groupName).Str("gid", group.Gid).Msg("Successfully retrieved group credentials")
	return group, nil
}
