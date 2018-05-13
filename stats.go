package main

import (
	"fmt"
	"github.com/alexey-sveshnikov/go-socks5"
	"gopkg.in/alexcesaro/statsd.v2"
	"sync"
	"time"
)

type StatsHandler struct {
	backend            StatsBackend
	activeSessionsLock sync.Mutex
	activeSessions     map[string]time.Time
	count              int
}

type StatsBackend interface {
	incrementCounter(name string, value int)
	sendGauge(name string, value int)
}

type StatsdBackend struct {
	client *statsd.Client
	mutex  sync.Mutex
}

func NewStatsHandler(backend StatsBackend) *StatsHandler {
	handler := StatsHandler{
		backend:        backend,
		activeSessions: make(map[string]time.Time, 100),
	}

	go func() {
		for range time.Tick(time.Second * 10) {
			handler.activeSessionsLock.Lock()
			now := time.Now()
			for id := range handler.activeSessions {
				lastSeen := handler.activeSessions[id]
				diff := now.Sub(lastSeen)
				if diff.Seconds() > 30 {
					delete(handler.activeSessions, id)
				}
			}
			fmt.Printf("Active sessions: %d\n", len(handler.activeSessions))
			fmt.Printf("Momentally: %d\n", handler.count)
			handler.activeSessionsLock.Unlock()
			handler.backend.sendGauge("active_sessions", len(handler.activeSessions))
			handler.backend.sendGauge("client_connections", handler.count)
		}
	}()

	return &handler
}

func NewStatsdBackend(addr string) *StatsdBackend {
	client, err := statsd.New(
		statsd.Address(addr),
	)
	if err != nil {
		// This library checks if the statsd is available.
		// We definetly don't want to fail in case if the statsd is down.
		fmt.Printf("Error while setting up statsd: %s\n", err)
	}
	return &StatsdBackend{
		client: client,
	}
}

func (s *StatsdBackend) incrementCounter(name string, value int) {
	s.mutex.Lock()
	defer s.mutex.Unlock()
	//fmt.Printf("Increment counter %s by %d\n", name, value)
	s.client.Count(name, value)
}

func (s *StatsdBackend) sendGauge(name string, value int) {
	s.mutex.Lock()
	defer s.mutex.Unlock()
	//fmt.Printf("Increment counter %s by %d\n", name, value)
	s.client.Gauge(name, value)
}

func (h StatsHandler) OnSessionStarted(request *socks5.Request) {
	h.backend.incrementCounter("connections", 1)
	h.count += 1
}

func (h StatsHandler) OnSessionFinished(request *socks5.Request, sessionLength time.Duration) {
	h.count -= 1
}

func (h StatsHandler) OnSessionBlocked(request *socks5.Request) {
	h.backend.incrementCounter("connections.blocked", 1)
}

func (h StatsHandler) OnUploadBytes(request *socks5.Request, bytes int64) {
	h.activeSessionsLock.Lock()
	h.activeSessions[request.RemoteAddr.String()] = time.Now()
	h.activeSessionsLock.Unlock()
	h.backend.incrementCounter("traffic.uploaded", int(bytes))
}

func (h StatsHandler) OnDownloadBytes(request *socks5.Request, bytes int64) {
	h.backend.incrementCounter("traffic.download", int(bytes))
}

func (h StatsHandler) OnProxiedConnectionStarted(request *socks5.Request, remoteAddr string) {
}
