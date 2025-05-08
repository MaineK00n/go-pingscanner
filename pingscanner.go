/*
Package pingscanner scan alive IPs of the given CIDR range in parallel.
*/
package pingscanner

import (
	"net"
	"os/exec"
	"slices"
	"strings"
	"sync"
)

// PingScanner has information of Scanning.
type PingScanner struct {
	// CIDR (ex. 192.168.0.0/24)
	CIDR string

	// Number of concurrency ping process. (ex. 100)
	NumOfConcurrency int

	// ping command options. (ex. []string{"-c1", "-t1"})
	PingOptions []string
}

type pong struct {
	IP    string
	Alive bool
}

// Scan ping to hosts in CIDR range.
func (d PingScanner) Scan() (aliveIPs []string, err error) {
	hostsInCidr, err := expandCidrIntoIPs(d.CIDR)
	if err != nil {
		return nil, err
	}

	pongChan := make(chan pong, len(hostsInCidr))
	limit := make(chan struct{}, d.NumOfConcurrency)

	var wg sync.WaitGroup
	wg.Add(len(hostsInCidr))
	for _, ip := range hostsInCidr {
		ip := ip
		limit <- struct{}{}
		go func() {
			pongChan <- pong{
				IP:    ip,
				Alive: ping(append(slices.Clone(d.PingOptions), ip)...),
			}
			<-limit
			wg.Done()
		}()
	}

	go func() {
		wg.Wait()
		close(limit)
		close(pongChan)
	}()

	for pong := range pongChan {
		if pong.Alive {
			aliveIPs = append(aliveIPs, pong.IP)
		}
	}

	return
}

func expandCidrIntoIPs(cidr string) ([]string, error) {
	splitted := strings.Split(cidr, "/")
	if len(splitted) == 1 || splitted[1] == "32" {
		return []string{splitted[0]}, nil
	}
	ip, ipnet, err := net.ParseCIDR(cidr)
	if err != nil {
		return nil, err
	}

	var ips []string
	for ip := ip.Mask(ipnet.Mask); ipnet.Contains(ip); inc(ip) {
		ips = append(ips, ip.String())
	}
	// remove network address and broadcast address
	return ips[1 : len(ips)-1], nil
}

// http://play.golang.org/p/m8TNTtygK0
func inc(ip net.IP) {
	for j := len(ip) - 1; j >= 0; j-- {
		ip[j]++
		if ip[j] > 0 {
			break
		}
	}
}

func ping(args ...string) bool {
	_, err := exec.Command("ping", args...).Output()
	return err == nil
}
