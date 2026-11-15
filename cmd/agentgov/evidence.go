// SPDX-License-Identifier: Apache-2.0

package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/spf13/cobra"

	"github.com/shahzadarain/agent-governance-auditor/internal/discovery"
	"github.com/shahzadarain/agent-governance-auditor/internal/evidence"
)

func newEvidenceCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "evidence",
		Short: "Bind, sign, and verify test or runtime evidence files",
		Long: `Work with external evidence files.

A static scan can show that a control is implemented. It cannot show that
the control was tested or works in operation. That proof comes from
evidence files written by your tests or your runtime, bound to the exact
file content or commit, and optionally signed.`,
	}

	var root string
	digest := &cobra.Command{
		Use:     "digest <path>...",
		Short:   "Print the content digest that binds evidence to these files",
		Example: `  agentgov evidence digest src/dispatch.py tests/governance/test_allowlist.py`,
		Args:    cobra.MinimumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			d, err := evidence.SubjectDigest(root, args)
			if err != nil {
				return err
			}
			fmt.Fprintln(cmd.OutOrStdout(), d)
			return nil
		},
	}
	digest.Flags().StringVar(&root, "root", ".", "repository root that the paths are relative to")

	var outDir string
	keygen := &cobra.Command{
		Use:   "keygen",
		Short: "Create an Ed25519 key pair for signing evidence",
		Long: `Create an Ed25519 key pair for signing evidence.

Keep the private key in your CI secret store, outside the repository.
Give the public key to the people who run scans (--trust-key).`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			pub, priv, err := ed25519.GenerateKey(rand.Reader)
			if err != nil {
				return err
			}
			privPath := filepath.Join(outDir, "agentgov-evidence.key")
			pubPath := filepath.Join(outDir, "agentgov-evidence.pub")
			for _, p := range []string{privPath, pubPath} {
				if _, err := os.Stat(p); err == nil {
					return fmt.Errorf("%s already exists; move it first", p)
				}
			}
			if err := os.MkdirAll(outDir, 0o755); err != nil {
				return err
			}
			if err := os.WriteFile(privPath, []byte(base64.StdEncoding.EncodeToString(priv)+"\n"), 0o600); err != nil {
				return err
			}
			if err := os.WriteFile(pubPath, []byte(base64.StdEncoding.EncodeToString(pub)+"\n"), 0o644); err != nil {
				return err
			}
			out := cmd.OutOrStdout()
			fmt.Fprintf(out, "Private key: %s  (keep secret; never commit it)\n", privPath)
			fmt.Fprintf(out, "Public key:  %s  (share; use with --trust-key)\n", pubPath)
			return nil
		},
	}
	keygen.Flags().StringVar(&outDir, "out-dir", ".", "folder to write the key files to")

	var keyPath string
	sign := &cobra.Command{
		Use:     "sign <evidence.json>",
		Short:   "Sign every item in an evidence file",
		Example: `  agentgov evidence sign .agentgov/evidence/governance-tests.json --key agentgov-evidence.key`,
		Args:    cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			raw, err := readKeyFile(keyPath, ed25519.PrivateKeySize)
			if err != nil {
				return fmt.Errorf("private key: %w", err)
			}
			n, err := evidence.SignFile(args[0], ed25519.PrivateKey(raw))
			if err != nil {
				return err
			}
			fmt.Fprintf(cmd.OutOrStdout(), "Signed %d evidence item(s) in %s\n", n, args[0])
			return nil
		},
	}
	sign.Flags().StringVar(&keyPath, "key", "", "Ed25519 private key file from \"agentgov evidence keygen\"")
	_ = sign.MarkFlagRequired("key")

	var trust []string
	var verifyRoot string
	verify := &cobra.Command{
		Use:   "verify <evidence.json>",
		Short: "Check binding, expiry, and signatures of an evidence file",
		Example: `  agentgov evidence verify .agentgov/evidence/governance-tests.json
  agentgov evidence verify evidence.json --trust-key agentgov-evidence.pub`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			keys, err := loadPublicKeys(trust)
			if err != nil {
				return err
			}
			absRoot, err := filepath.Abs(verifyRoot)
			if err != nil {
				return err
			}
			commit := discovery.ReadCommit(absRoot)
			items, problems := evidence.VerifyFile(absRoot, args[0], commit, time.Now().UTC(), keys)
			out := cmd.OutOrStdout()
			bad := len(problems)
			for _, it := range items {
				line := fmt.Sprintf("%s  %-8s validity=%s integrity=%s", it.ControlID, it.Result, it.Validity, it.Integrity)
				if it.ValidityReason != "" {
					line += "  (" + it.ValidityReason + ")"
				}
				fmt.Fprintln(out, line)
				if it.Validity != "valid" {
					bad++
				}
			}
			for _, p := range problems {
				fmt.Fprintf(out, "problem: %s\n", p)
			}
			if bad > 0 {
				return fmt.Errorf("%d evidence problem(s) found", bad)
			}
			fmt.Fprintf(out, "%d evidence item(s) are valid for the current content.\n", len(items))
			return nil
		},
	}
	verify.Flags().StringSliceVar(&trust, "trust-key", nil, "Ed25519 public key file (repeatable)")
	verify.Flags().StringVar(&verifyRoot, "root", ".", "repository root the evidence refers to")

	cmd.AddCommand(digest, keygen, sign, verify)
	return cmd
}
