// Copyright © 2017 uxbh
// This file is part of github.com/uxbh/ztdns.

package ztapi

import "fmt"

// GetNetworkInfo returns a Nework containing information about a ZeroTier network
func GetNetworkInfo(API, host, networkID string) (*Network, error) {
	resp := new(Network)
	url := fmt.Sprintf("%s/network/%s", host, networkID)
	err := getJSON(url, API, resp)
	if err != nil {
		return nil, fmt.Errorf("Unable to get network info: %s", err.Error())
	}
	return resp, nil
}

// Network contains the JSON response for a request for a network
type Network struct {
	ID                string      `json:"id,omitempty"`
	Type              string      `json:"type,omitempty"`
	Clock             int64       `json:"clock,omitempty"`
	UI                UI          `json:"ui,omitempty"`
	Config            Config      `json:"config,omitempty"`
	Description       string      `json:"description,omitempty"`
	OnlineMemberCount int64       `json:"onlineMemberCount,omitempty"`
	Permissions       Permissions `json:"permissions,omitempty"`
	RulesSource       string      `json:"rulesSource,omitempty"`
	TagsByName        TagsByName  `json:"tagsByName,omitempty"`
}

type Config struct {
	ActiveMemberCount     int64        `json:"activeMemberCount,omitempty"`
	AuthTokens            []string     `json:"authTokens,omitempty"`
	AuthorizedMemberCount int64        `json:"authorizedMemberCount,omitempty"`
	Capabilities          []Capabilities     `json:"capabilities,omitempty"`
	Clock                 int64        `json:"clock,omitempty"`
	CreationTime          int64        `json:"creationTime,omitempty"`
	ID                    string       `json:"id,omitempty"`
	LastModified          int64        `json:"lastModified,omitempty"`
	MulticastLimit        int64        `json:"multicastLimit,omitempty"`
	Name                  string       `json:"name,omitempty"`
	Nwid                  string       `json:"nwid,omitempty"`
	Objtype               string       `json:"objtype,omitempty"`
	Private               bool         `json:"private,omitempty"`
	Revision              int64        `json:"revision,omitempty"`
	Routes                []Routes     `json:"routes,omitempty"`
	Rules                 []Rules      `json:"rules,omitempty"`
	Tags                  []Properties    `json:"tags,omitempty"`
	TotalMemberCount      int64        `json:"totalMemberCount,omitempty"`
	V4AssignMode          V4AssignMode `json:"v4AssignMode,omitempty"`
	V6AssignMode          V6AssignMode `json:"v6AssignMode,omitempty"`
}

type Routes struct {
	Target string `json:"target,omitempty"`
	Via    string `json:"via,omitempty"`
}

type Rules struct {
	EtherType int64  `json:"ethertype,omitempty"`
	Not       bool   `json:"not,omitempty"`
	Or        bool   `json:"or,omitempty"`
	Type      string `json:"type,omitempty"`
}

type V4AssignMode struct {
	Properties Properties `json:"properties,omitempty"`
}

type V6AssignMode struct {
	Sixplane bool `json:"6plane"`
	Rfc4193  bool
	Zt       bool
}

type Capabilities struct {
		Default bool
		ID int
		Rules []struct {
			Type string
		}
}
type UI struct {
	Properties Properties `json:"properties,omitempty"`
}

type TagsByName struct {
	Properties Properties `json:"properties,omitempty"`
}

type Properties struct{}

type Permissions struct {
	ID ID `json:"{id},omitempty"`
}

type ID struct {
	A bool `json:"a,omitempty"`
	D bool `json:"d,omitempty"`
	M bool `json:"m,omitempty"`
	O bool `json:"o,omitempty"`
	R bool `json:"r,omitempty"`
	T bool `json:"t,omitempty"`
}
