// SPDX-License-Identifier: Apache-2.0
// Copyright 2023 VMware, Inc.

package system

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"time"

	"github.com/rs/zerolog/log"

	"github.com/vmware/network-event-broker/pkg/conf"
)

// defaultScriptTimeout defines the maximum duration for script execution.
const defaultScriptTimeout = 5 * time.Second

// ExecuteScripts runs scripts in the routes-modified.d directory for a given link.
func ExecuteScripts(link string, index int) error {
	if link == "" {
		log.Error().Msg("Link name cannot be empty")
		return fmt.Errorf("link name cannot be empty")
	}
	if index < 0 {
		log.Error().Int("index", index).Msg("Invalid link index")
		return fmt.Errorf("invalid link index: %d", index)
	}

	scriptDir := filepath.Join(conf.ConfPath, conf.RoutesModifiedDir)
	scripts, err := ReadAllScriptInConfDir(scriptDir)
	if err != nil {
		log.Error().Str("dir", scriptDir).Err(err).Msg("Failed to read script directory")
		return fmt.Errorf("failed to read script directory %s: %w", scriptDir, err)
	}

	if len(scripts) == 0 {
		log.Debug().Str("dir", scriptDir).Msg("No scripts found in directory")
		return nil
	}

	// Prepare environment variables.
	env := append(os.Environ(),
		"LINK="+link,
		"LINKINDEX="+strconv.Itoa(index),
	)

	for _, script := range scripts {
		scriptPath := filepath.Join(scriptDir, script)
		log.Debug().Str("script", scriptPath).Str("link", link).Int("index", index).Msg("Executing script")

		// Use context to enforce timeout.
		ctx, cancel := context.WithTimeout(context.Background(), defaultScriptTimeout)
		defer cancel()

		cmd := exec.CommandContext(ctx, scriptPath)
		cmd.Env = env

		if err := cmd.Run(); err != nil {
			log.Error().Str("script", scriptPath).Str("link", link).Int("index", index).Err(err).Msg("Failed to execute script")
			continue
		}

		log.Debug().Str("script", scriptPath).Str("link", link).Int("index", index).Msg("Successfully executed script")
	}

	log.Debug().Str("dir", scriptDir).Int("count", len(scripts)).Str("link", link).Int("index", index).Msg("Completed script execution")
	return nil
}
