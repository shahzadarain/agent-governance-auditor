// SPDX-License-Identifier: Apache-2.0

// Package config defines and loads the .agentgov.yaml configuration file.
// This file holds the types only; loading and validation live in load.go.
//
// A configuration file is optional. A zero-config scan must work. Content of
// the file is a declaration by the repository author: it can describe the
// agent and raise requirements, but it is never evidence that a control is
// implemented, and it cannot weaken an organization baseline supplied
// outside the repository.
package config

// FileName is the default configuration file name.
const FileName = ".agentgov.yaml"

// CurrentSchemaVersion is the supported configuration schema version.
const CurrentSchemaVersion = "1"

// Config is the parsed .agentgov.yaml document.
type Config struct {
	SchemaVersion string       `yaml:"schema_version" json:"schema_version"`
	Agent         Agent        `yaml:"agent" json:"agent"`
	Agents        []Agent      `yaml:"agents,omitempty" json:"agents,omitempty"` // monorepos: several agents, each with a root
	Capabilities  Capabilities `yaml:"capabilities" json:"capabilities"`
	Verification  Verification `yaml:"verification" json:"verification"`
	Policy        Policy       `yaml:"policy" json:"policy"`
	Report        Report       `yaml:"report" json:"report"`
	Scan          Scan         `yaml:"scan" json:"scan"`

	// Path is the repo-relative path the configuration was loaded from.
	// It is set by the loader and is not part of the file.
	Path string `yaml:"-" json:"-"`
}

// Agent is the declared agent metadata (control AGC-001 and AGC-002 inputs).
type Agent struct {
	ID                 string `yaml:"id" json:"id"`
	Root               string `yaml:"root,omitempty" json:"root,omitempty"` // repo-relative directory; default "."
	Owner              string `yaml:"owner" json:"owner"`
	Description        string `yaml:"description" json:"description"`
	Purpose            string `yaml:"purpose,omitempty" json:"purpose,omitempty"`
	RiskTier           string `yaml:"risk_tier" json:"risk_tier"` // low | medium | high
	RiskRationale      string `yaml:"risk_rationale,omitempty" json:"risk_rationale,omitempty"`
	DataClassification string `yaml:"data_classification" json:"data_classification"` // public | internal | confidential | restricted
	RegistryRef        string `yaml:"registry_ref,omitempty" json:"registry_ref,omitempty"`
	LastReviewed       string `yaml:"last_reviewed,omitempty" json:"last_reviewed,omitempty"` // YYYY-MM-DD
	Reviewer           string `yaml:"reviewer,omitempty" json:"reviewer,omitempty"`
}

// Capabilities declares what the agent is allowed to do.
type Capabilities struct {
	DeclaredTools        []string `yaml:"declared_tools" json:"declared_tools"`
	SensitiveActions     []string `yaml:"sensitive_actions" json:"sensitive_actions"`
	ExternalConnectivity *bool    `yaml:"external_connectivity,omitempty" json:"external_connectivity,omitempty"`
}

// Verification configures how evidence is gathered.
type Verification struct {
	Profile       string   `yaml:"profile" json:"profile"`               // baseline | standard | high-risk
	TestsPath     string   `yaml:"tests_path" json:"tests_path"`         // repo-relative
	EvidencePaths []string `yaml:"evidence_paths" json:"evidence_paths"` // repo-relative directories of evidence JSON
	Offline       *bool    `yaml:"offline,omitempty" json:"offline,omitempty"`
}

// Exception records an approved not-applicable decision or an accepted risk.
type Exception struct {
	Control    string `yaml:"control" json:"control"`
	Reason     string `yaml:"reason" json:"reason"`
	ApprovedBy string `yaml:"approved_by" json:"approved_by"`
	Expires    string `yaml:"expires,omitempty" json:"expires,omitempty"` // YYYY-MM-DD
}

// Policy selects the policy pack and may raise requirements.
type Policy struct {
	Pack              string      `yaml:"pack" json:"pack"` // builtin/v1
	MandatoryControls []string    `yaml:"mandatory_controls" json:"mandatory_controls"`
	MinMaturity       *int        `yaml:"min_maturity,omitempty" json:"min_maturity,omitempty"`
	NotApplicable     []Exception `yaml:"not_applicable,omitempty" json:"not_applicable,omitempty"`
	AcceptedRisks     []Exception `yaml:"accepted_risks,omitempty" json:"accepted_risks,omitempty"`
}

// Report configures report output.
type Report struct {
	RedactSensitiveData *bool    `yaml:"redact_sensitive_data,omitempty" json:"redact_sensitive_data,omitempty"`
	Formats             []string `yaml:"formats" json:"formats"`
}

// Scan configures file discovery.
type Scan struct {
	Include     []string `yaml:"include,omitempty" json:"include,omitempty"` // glob patterns, repo-relative
	Exclude     []string `yaml:"exclude,omitempty" json:"exclude,omitempty"`
	MaxFileSize int64    `yaml:"max_file_size,omitempty" json:"max_file_size,omitempty"` // bytes
}
