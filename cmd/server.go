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
	//"github.com/miekg/dns"
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

		if viper.GetBool("show_offline_nodes"){
			offline_nodes = true
			log.Debug("Creating records for offline nodes, too.")
		}

		if viper.GetBool("enable_tag_cname_records"){
			tag_records = true
			log.Debug("Enabling tag-based CNAME records.")
		}

		// Update the DNSDatabase
		lastUpdate := updateDNS(offline_nodes, tag_records)
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
				lastUpdate = updateDNS(offline_nodes, tag_records)
			}
		}
	},
}

func init() {
	RootCmd.AddCommand(serverCmd)
	serverCmd.PersistentFlags().String("interface", "", "interface to listen on")
	viper.BindPFlag("interface", serverCmd.PersistentFlags().Lookup("interface"))
}

func updateDNS(offline_nodes bool, tag_records bool) time.Time {
	var suffix_used bool
	suffix_used = true
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
				record := n.Name + "." + domain + "."
				record_suffix := domain + "."
				if suffix_used {
					record = record + suffix + "."
					record_suffix = record_suffix + suffix + "."
				}
				dnssrv.DNSDatabase[record] = dnssrv.Records{}
				ip6 := []net.IP{}
				ip4 := []net.IP{}
				cname := []string{}
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
						cname = append(cname, fmt.Sprintf("%d", t) + "." + record_suffix)
					}
				}
				// Get the rest of the address assigned to the member
				for _, a := range n.Config.IPAssignments {
					ip4 = append(ip4, net.ParseIP(a))
				}
				// Add the record to the database
				if tag_records {
					log.Infof("Updating %-15s IPv4: %-15s IPv6: %-15s CNAME %s", record, ip4, ip6, cname)
					dnssrv.DNSDatabase[record] = dnssrv.Records{
						A:    ip4,
						AAAA: ip6,
						CNAME: cname,
					}
				} else {
					log.Infof("Updating %-15s IPv4: %-15s IPv6: %s", record, ip4, ip6)
					dnssrv.DNSDatabase[record] = dnssrv.Records{
						A:    ip4,
						AAAA: ip6,
					}
				}
			}
		}
	}

	// Return the current update time
	return time.Now()
}
