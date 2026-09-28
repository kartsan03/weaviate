//                           _       _
// __      _____  __ ___   ___  __ _| |_ ___
// \ \ /\ / / _ \/ _` \ \ / / |/ _` | __/ _ \
//  \ V  V /  __/ (_| |\ V /| | (_| | ||  __/
//   \_/\_/ \___|\__,_| \_/ |_|\__,_|\__\___|
//
//  Copyright © 2016 - 2026 Weaviate B.V. All rights reserved.
//
//  CONTACT: hello@weaviate.io
//

package rbacconf

import (
	"fmt"
	"slices"
	"strings"

	"github.com/weaviate/weaviate/usecases/auth/authentication"
	"github.com/weaviate/weaviate/usecases/auth/authorization"
	"github.com/weaviate/weaviate/usecases/auth/authorization/conv"
)

// Config makes every subject on the list an admin, whereas everyone else
// has no rights whatsoever
type Config struct {
	Enabled           bool     `json:"enabled" yaml:"enabled"`
	RootUsers         []string `json:"root_users" yaml:"root_users"`
	RootGroups        []string `json:"root_groups" yaml:"root_groups"`
	ReadOnlyGroups    []string `json:"readonly_groups" yaml:"readonly_groups"`
	ViewerUsers       []string `json:"viewer_users" yaml:"viewer_users"`
	AdminUsers        []string `json:"admin_users" yaml:"admin_users"`
	IpInAuditDisabled bool     `json:"ip_in_audit" yaml:"ip_in_audit"`
}

// Validate admin list config for viability, can be called from the central
// config package
func (c Config) Validate() error {
	oidcUser := func(s string) string { return conv.UserNameWithTypeFromId(s, authentication.AuthTypeOIDC) }
	// applyPredefinedRoles writes each non-blank subject to policy.csv, and Init
	// loads that file before it applies this config again. A row that doesn't
	// read back unchanged fails that load or loads as a different grant. A user
	// list's oidc: row is at least as long as its db: row, so it checks both.
	for _, list := range []struct {
		name     string
		subjects []string
		subject  func(string) string
		role     string
	}{
		{name: "root_users", subjects: c.RootUsers, subject: oidcUser, role: authorization.Root},
		{name: "admin_users", subjects: c.AdminUsers, subject: oidcUser, role: authorization.Admin},
		{name: "viewer_users", subjects: c.ViewerUsers, subject: oidcUser, role: authorization.Viewer},
		{name: "root_groups", subjects: c.RootGroups, subject: conv.PrefixGroupName, role: authorization.Root},
		{name: "readonly_groups", subjects: c.ReadOnlyGroups, subject: conv.PrefixGroupName, role: authorization.ReadOnly},
	} {
		for _, subject := range list.subjects {
			if strings.TrimSpace(subject) == "" {
				continue
			}
			if err := conv.ValidateStorableRow("g", list.subject(subject), conv.PrefixRoleName(list.role)); err != nil {
				return fmt.Errorf("%s: %w", list.name, err)
			}
		}
	}
	return nil
}

// IsRootUser reports whether a principal with the given username and groups
// would be granted the root role via the static RootUsers/RootGroups
// bindings. username must be the same form casbin sees — i.e. the
// namespace-qualified name on namespace-enabled clusters.
func (c Config) IsRootUser(username string, groups []string) bool {
	for _, group := range groups {
		if slices.Contains(c.RootGroups, group) {
			return true
		}
	}
	return slices.Contains(c.RootUsers, username)
}
