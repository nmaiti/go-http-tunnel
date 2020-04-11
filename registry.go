// Copyright (C) 2017 Michał Matczuk
// Use of this source code is governed by an AGPL-style
// license that can be found in the LICENSE file.

package tunnel

import (
	"fmt"
	"net"
	"sync"

	"github.com/mmatczuk/go-http-tunnel/log"
)

// RegistryItem holds information about hosts and listeners associated with a
// client.
type RegistryItem struct {
	Hosts         []*HostAuth
	Listeners     []net.Listener
	ListenerNames []string
	ClientName    string
	ClientID      string
}

// HostAuth holds host and authentication info.
type HostAuth struct {
	Host string
	Auth *Auth
}

type hostInfo struct {
	identifier string
	auth       *Auth
}

type registry struct {
	source map[string]*RegistryItem //Origin Address based on host:port
	items  map[string]*RegistryItem //Client name
	hosts  map[string]*hostInfo
	mu     sync.RWMutex
	logger log.Logger
}

func newRegistry(logger log.Logger) *registry {
	if logger == nil {
		logger = log.NewNopLogger()
	}

	return &registry{
		items:  make(map[string]*RegistryItem),
		source: make(map[string]*RegistryItem),
		hosts:  make(map[string]*hostInfo),
		logger: logger,
	}
}

func (r *registry) PreSubscribe(origaddr string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, ok := r.source[origaddr]; ok {
		r.logger.Log(
			"level", 0,
			"action", "error on pre-subscribe to registry this entry already exist",
			"identifier", origaddr,
		)
		return
	}
	r.source[origaddr] = &RegistryItem{ClientID: origaddr}
}

// Subscribe allows to connect client with a given identifier.
func (r *registry) Subscribe(cname string, origaddr string) {
	r.mu.Lock()
	defer r.mu.Unlock()

	if _, ok := r.items[cname]; ok {
		r.logger.Log(
			"level", 0,
			"action", "error on subscribe to registry this entry already exist",
			"identifier", origaddr,
		)
		return
	}
	reg := r.source[origaddr]
	reg.ClientName = cname
	//fmt.Printf("SUBSCRIBE REGISTRY Client Name: [%s] Client ID: [%s] value : %+v \n", cname, origaddr, reg)
	r.items[cname] = reg
	r.logger.Log(
		"level", 2,
		"action", "REGISTRY SUBSCRIBE",
		"client-name", cname,
		"client-id", origaddr,
		"data", reg,
	)
}

// GetID returns the ID for this client
func (r *registry) GetID(cname string) string {
	r.mu.RLock()
	defer r.mu.RUnlock()
	v, ok := r.items[cname]
	if !ok {
		fmt.Errorf("NO ID in %s\n", cname)
		return ""
	}
	return v.ClientID
}

// IsSubscribed returns true if client is subscribed.
/*func (r *registry) IsSubscribed(identifier string) bool {
	r.mu.RLock()
	defer r.mu.RUnlock()
	fmt.Printf("IS SUBSCRIBED REGISTRY [%s] \n", identifier)

	_, ok := r.items[identifier]
	return ok
}*/

// Subscriber returns client identifier assigned to given host.
func (r *registry) Subscriber(hostPort string) (string, *Auth, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	h, ok := r.hosts[trimPort(hostPort)]
	if !ok {
		return "", nil, false
	}
	fmt.Printf("SUBSCRIBER REGISTRY [%s] value : %+v \n", hostPort, h)

	return h.identifier, h.auth, ok
}

// Unsubscribe removes client from registry and returns it's RegistryItem.
func (r *registry) Unsubscribe(identifier string, idname string) *RegistryItem {
	r.mu.Lock()
	defer r.mu.Unlock()

	i, ok := r.items[identifier]
	if !ok {
		fmt.Printf("UNSUBSCRIBE REGISTRY error not found ID [%s] Idname [%s] value : %+v \n", identifier, idname, i)
		return nil
	}
	fmt.Printf("UNSUBSCRIBE REGISTRY Identifier [%s] Idname [%s] value : %+v \n", identifier, idname, i)

	r.logger.Log(
		"level", 1,
		"action", "REGISTRY UNSUBSCRIBE",
		"identifier", identifier,
		"id-name", idname,
		"data", i,
	)

	if i.Hosts != nil {
		for _, h := range i.Hosts {
			delete(r.hosts, h.Host)
		}
	}

	delete(r.items, identifier)

	return i
}

func (r *registry) set(i *RegistryItem, identifier string) error {

	r.mu.Lock()
	defer r.mu.Unlock()

	j, ok := r.items[identifier]
	if !ok {
		r.logger.Log(
			"level", 1,
			"action", "REGISTRY SET ERROR: client-name not found",
			"client-id", i.ClientID,
			"client-name", identifier,
			"data", i,
		)
		return errClientNotSubscribed
	}
	r.logger.Log(
		"level", 2,
		"action", "REGISTRY SET (OLD FOUND)",
		"client-id", j.ClientID,
		"client-name", identifier,
		"data", j,
	)

	//fmt.Printf("OLD REGISTRY Identifier [%s] value : %+v \n", identifier, j)
	i.ClientID = j.ClientID

	r.logger.Log(
		"level", 2,
		"action", "REGISTRY SET (NEW SET)",
		"client-id", i.ClientID,
		"client-name", identifier,
		"data", i,
	)

	if i.Hosts != nil {
		for _, h := range i.Hosts {
			if h.Auth != nil && h.Auth.User == "" {
				return fmt.Errorf("missing auth user")
			}
			if _, ok := r.hosts[trimPort(h.Host)]; ok {
				return fmt.Errorf("host %q is occupied", h.Host)
			}
		}

		for _, h := range i.Hosts {
			r.hosts[trimPort(h.Host)] = &hostInfo{
				identifier: identifier,
				auth:       h.Auth,
			}
		}
	}
	//fmt.Printf("SET REGISTRY Identifier [%s] value : %+v \n", identifier, i)
	r.items[identifier] = i
	r.source[i.ClientID] = i

	return nil
}

func (r *registry) clear(identifier string) *RegistryItem {

	r.mu.Lock()
	defer r.mu.Unlock()

	//i, ok := r.items[identifier]
	i, ok := r.source[identifier]
	if !ok || i == nil {
		r.logger.Log(
			"level", 2,
			"action", "error on clear register",
			"identifier", identifier,
			"register-exist", ok,
		)
		return nil
	}
	//fmt.Printf("CLEAR REGISTRY Identifier [%s] value : %+v \n", identifier, i)

	r.logger.Log(
		"level", 2,
		"action", "REGISTRY CLEAR item",
		"identifier", identifier,
		"client-name", i.ClientName,
		"client-id", i.ClientID,
		"data", i,
	)

	if i.Hosts != nil {
		for _, h := range i.Hosts {
			r.logger.Log(
				"level", 2,
				"action", "REGISTRI CLEAR (delete hosts)",
				"identifier", identifier,
				"client-name", i.ClientName,
				"client-id", i.ClientID,
				"host", h.Host,
				"trimport", trimPort(h.Host),
			)
			delete(r.hosts, trimPort(h.Host))
		}
	}

	r.source[identifier] = nil
	r.items[i.ClientName] = nil
	delete(r.source, identifier)
	delete(r.items, i.ClientName)
	return i
}

func trimPort(hostPort string) (host string) {
	host, _, _ = net.SplitHostPort(hostPort)
	if host == "" {
		host = hostPort
	}
	return
}
