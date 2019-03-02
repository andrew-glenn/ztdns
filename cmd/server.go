// Copyright © 2017 uxbh
// This file is part of github.com/uxbh/ztdns.

package cmd

import (
	"fmt"
	"net"
	"time"

	log "github.com/Sirupsen/logrus"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"github.com/uxbh/ztdns/dnssrv"
	"github.com/uxbh/ztdns/ztapi"
	"strconv"
	"strings"
	// "github.com/tidwall/gjson"
)

// serverCmd represents the server command
var serverCmd = &cobra.Command{
	Use:   "server",
	Short: "Run ztDNS server",
	Long: `Server (ztdns server) will start the DNS server.append

	Example: ztdns server`,
	PreRunE: func(cmd *cobra.Command, args []string) error {
		// Check config and bail if anything important is missing.
		if viper.GetBool("debug") {
			log.SetLevel(log.DebugLevel)
			log.Debug("Setting Debug Mode")
		}
		if viper.GetString("ZT.API") == "" {
			return fmt.Errorf("no API key provided")
		}
		if len(viper.GetStringMapString("Networks")) == 0 {
			return fmt.Errorf("no Domain / Network ID pairs Provided")
		}
		if viper.GetString("ZT.URL") == "" {
			return fmt.Errorf("no URL provided. Run ztdns mkconfig first")
		}
		return nil
	},
	Run: func(cmd *cobra.Command, args []string) {
		var offline_nodes bool
		var tag_records bool
		var reverse_dns bool

		if viper.GetBool("show_offline_nodes"){
			offline_nodes = true
			log.Debug("Creating records for offline nodes, too.")
		}

		if viper.GetBool("enable_tag_cname_records"){
			tag_records = true
			log.Debug("Enabling tag-based CNAME records.")
		}

		if viper.GetBool("reverse_dns"){
			reverse_dns = true
		}
		// Update the DNSDatabase
		lastUpdate := updateDNS(offline_nodes, tag_records, reverse_dns)
		req := make(chan string)
		// Start the DNS server
		go dnssrv.Start(viper.GetString("interface"), viper.GetInt("port"), viper.GetString("suffix"), req)

		refresh := viper.GetInt("DbRefresh")
		if refresh == 0 {
			refresh = 30
		}
		for {
			// Block until a new request comes in
			n := <-req
			log.Debugf("Got request for %s", n)
			// If the database hasn't been updated in the last "refresh" minutes, update it.
			if time.Since(lastUpdate) > time.Duration(refresh)*time.Minute {
				log.Infof("DNSDatabase is stale. Refreshing.")
				lastUpdate = updateDNS(offline_nodes, tag_records, reverse_dns)
			}
		}
	},
}

func init() {
	RootCmd.AddCommand(serverCmd)
	serverCmd.PersistentFlags().String("interface", "", "interface to listen on")
	viper.BindPFlag("interface", serverCmd.PersistentFlags().Lookup("interface"))
}

func formatName(name string) string {
	name = strings.ToLower(name)
	name = strings.Replace(name, " ", "-", -1)
	return name
}

func updateDNS(offline_nodes bool, tag_records bool, reverse_dns bool) time.Time {
	var suffix_used bool
	var cname_tag_map map[string]string
	var cname_record_map map[string][]string
	suffix_used = true
	cname_tag_map = make(map[string]string)
	cname_record_map = make(map[string][]string)

	// Get config info
	API := viper.GetString("ZT.API")
	URL := viper.GetString("ZT.URL")
	suffix := viper.GetString("suffix")

	if suffix == "" {
		suffix_used = false
	}

	// Get all configured networks:
	for domain, id := range viper.GetStringMapString("Networks") {
		// Get ZeroTier Network info
		ztnetwork, err := ztapi.GetNetworkInfo(API, URL, id)
		if err != nil {
			log.Fatalf("Unable to update DNS entries: %s", err.Error())
		}
		if tag_records{
			m := ztnetwork.TagsByName
			for k,v := range m{
				mtag := k
				mid := strconv.Itoa(v.ID)
				for x,y := range v.ENUMS{
					y := strconv.Itoa(y)
					cname_tag_map[mid + " " + y] = x + "." + mtag
				}
			}
		}

		// Get list of members in network
		log.Infof("Getting Members of Network: %s (%s)", ztnetwork.Config.Name, domain)
		lst, err := ztapi.GetMemberList(API, URL, ztnetwork.ID)
		if err != nil {
			log.Fatalf("Unable to update DNS entries: %s", err.Error())
		}
		log.Infof("Got %d members", len(*lst))

		for _, n := range *lst {
			// For all online members
			if (offline_nodes || n.Online) {
				// Clear current DNS records
				record := formatName(n.Name) + "." + domain + "."
				record_suffix := domain + "."
				if suffix_used {
					record = record + suffix + "."
					record_suffix = record_suffix + suffix + "."
				}
				dnssrv.DNSDatabase[record] = dnssrv.Records{}
				ip6 := []net.IP{}
				ip4 := []net.IP{}
				// Get 6Plane address if network has it enabled
				if ztnetwork.Config.V6AssignMode.Sixplane {
					ip6 = append(ip6, n.Get6Plane())
				}
				// Get RFC4193 address if network has it enabled
				if ztnetwork.Config.V6AssignMode.Rfc4193 {
					ip6 = append(ip6, n.GetRFC4193())
				}

				// Fetch tags.
				if tag_records {
					for _, t := range n.Config.Tags {
						key := fmt.Sprintf("%d %d", t[0], t[1])
						text := cname_tag_map[key] + "." + record_suffix
						cname_record_map[text] = append(cname_record_map[text], record)
					}
				}
				// Get the rest of the address assigned to the member
				for _, a := range n.Config.IPAssignments {
					ip4 = append(ip4, net.ParseIP(a))
				}
				// Add the record to the database
				log.Infof("Updating %-15s IPv4: %-15s IPv6: %s", record, ip4, ip6)
				dnssrv.DNSDatabase[record] = dnssrv.Records{
					A:    ip4,
					AAAA: ip6,
				}
				if reverse_dns {
					for _, addr := range ip4 {
						log.Infof("Adding PTR record for %s", addr.String())
						dnssrv.DNSDatabase[addr.String()] = dnssrv.Records{
							PTR: record,
						}
					}
					for _, addr := range ip6 {
						log.Infof("Adding PTR record for %s", addr.String())
						dnssrv.DNSDatabase[addr.String()] = dnssrv.Records{
							PTR: record,
						}
					}
				}
			}
		}
	}
	for record_name, record_value := range cname_record_map{
		for individ_record := range record_value {
			log.Infof("Updating %-15s with record %s", record_name, record_value[individ_record])
		}
		dnssrv.DNSDatabase[record_name] = dnssrv.Records{
			CNAME: record_value,
		}
	}
	return time.Now()
}
