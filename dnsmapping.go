// dnsmapping.go
package dnsmapping

import (
	"bytes"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net"
	"os"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/mzimmerman/multicorecsv"
)

type dnsLine struct {
	ip       string
	hostname string
	day      time.Time
}

type DNSMapper struct {
	lock        sync.RWMutex
	dnsmap      map[string]dnsLine
	fname       string
	sleep       time.Duration
	needToWrite bool
}

func parseDNS(line []string) dnsLine {
	day := time.Date(2015, time.October, 0, 0, 0, 0, 0, time.UTC)
	if len(line) == 3 {
		var err error
		day, err = time.Parse("2006-01-02", line[2])
		if err != nil {
			// use default if it's not there
			day = time.Date(2015, time.October, 0, 0, 0, 0, 0, time.UTC)
		}
	}
	return dnsLine{
		ip:       line[1],
		hostname: line[0],
		day:      day,
	}
}

type DNSSlice []dnsLine

func (ds DNSSlice) Less(i, j int) bool {
	return ds[i].ip < ds[j].ip
}

func (ds DNSSlice) Len() int {
	return len(ds)
}

func (ds DNSSlice) Swap(i, j int) {
	ds[i], ds[j] = ds[j], ds[i]
}

var minSleepTime = time.Millisecond * 100
var maxSleepTime = time.Second * 30

func (d *DNSMapper) Lookup(ip net.IP) string { // either is successful or returns ip.String()
	str := ip.String()
	if ip.To4() == nil { // ipv6 address, skip them for now
		return ip.String()
	}
	d.lock.RLock()
	dns, ok := d.dnsmap[str]
	d.lock.RUnlock()
	if ok {
		return dns.hostname
	} else {
		d.lock.Lock() // lock here to stop concurrent network lookups
		defer d.lock.Unlock()
		time.Sleep(d.sleep)
		names, err := net.LookupAddr(str)
		if err != nil {
			log.Printf("Error looking up address - %s - %v", str, err)
			if strings.HasSuffix(err.Error(), "no such host") ||
				strings.HasSuffix(err.Error(), "server misbehaving") ||
				strings.HasSuffix(err.Error(), "Name or service not known") {
				names = append(names, str)
			} else {
				d.sleep *= 2
				if d.sleep > maxSleepTime {
					d.sleep = maxSleepTime
				}
				return str // timed out, don't write anything
			}
		}
		if len(names) == 0 {
			names = append(names, str)
		} else if names[0] == "" {
			log.Printf("IP %s is blank with lookup - %s", str, names[0])
			names[0] = str
		}
		dns = dnsLine{
			ip:       str,
			hostname: strings.Trim(names[0], "."),
			day:      time.Now(),
		}
		d.dnsmap[str] = dns
		d.needToWrite = true
		log.Printf("Lookup for %s found %s", dns.ip, dns.hostname)
		d.sleep = minSleepTime
		return dns.hostname
	}

}

func New(dnsFile string) (*DNSMapper, error) {
	dnsmap := make(map[string]dnsLine)
	dnsReader, err := os.Open(dnsFile)
	if err != nil {
		return nil, fmt.Errorf("Error opening dns mapping file - %v", err)
	}
	dnsCSV := multicorecsv.NewReader(dnsReader)
	dnsCSV.Comma = '\t'
	for {
		dnsLine, err := dnsCSV.Read()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, err
		}
		if dnsLine[0] == "" {
			dnsLine[0] = dnsLine[1]
		}
		if dnsLine[1] == "" {
			log.Printf("Missing IP address! - %s", dnsLine)
			continue
		}
		dns := parseDNS(dnsLine)
		dnsmap[dns.ip] = dns
	}
	dnsCSV.Close()
	return &DNSMapper{
		dnsmap: dnsmap,
		fname:  dnsFile,
	}, nil

}

func (d *DNSMapper) Close() error {
	d.lock.Lock()
	defer d.lock.Unlock()
	if !d.needToWrite {
		// nothing to write out, all done!
		return nil
	}
	dnsSlice := make(DNSSlice, 0, len(d.dnsmap))
	for _, dtmp := range d.dnsmap {
		dnsSlice = append(dnsSlice, dtmp)
	}
	sort.Sort(dnsSlice)
	tf, err := ioutil.TempFile("/tmp", "dnsFile")
	if err != nil {
		return fmt.Errorf("Error creating temporary file - %v", err)
	}
	var buf bytes.Buffer
	resultWriter := multicorecsv.NewWriter(io.MultiWriter(&buf, tf))
	resultWriter.Comma = '\t'
	for _, dns := range dnsSlice {
		err = resultWriter.Write([]string{dns.hostname, dns.ip, dns.day.Format("2006-01-02")})
		if err != nil {
			return fmt.Errorf("Error writing to file - %v", err)
		}
	}
	err = resultWriter.Close()
	if err == nil {
		log.Printf("Wrote out new file to %s", tf.Name())
		err = os.Remove(d.fname)
		if err == nil {
			err = ioutil.WriteFile(d.fname, buf.Bytes(), 0666)
		}
	}
	if err != nil {
		return fmt.Errorf("Error writing out and/or updating the new dns file - %v", err)
	}
	return nil
}
