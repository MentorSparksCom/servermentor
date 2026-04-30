package models

import "gorm.io/gorm"

type Server struct {
	gorm.Model
	Name       string `gorm:"uniqueIndex"`
	Provider   string
	IP         string
	OverlayIP  string
	RAM        string
	DiskSize   string
	Tags       string // Comma separated, or use a separate table
	KubeConfig string `gorm:"type:text"` // kluster login yaml
	Services   []Service
	Routes     []Route
}

type Service struct {
	gorm.Model
	ServerID    uint
	Name        string
	Namespace   string
	Type        string // ClusterIP, NodePort, LoadBalancer
	Deployments []Deployment
}

type Deployment struct {
	gorm.Model
	ServiceID   uint
	Name        string
	Namespace   string
	DockerImage string
	Replicas    int
}

type Route struct {
	gorm.Model
	ServerID       uint
	Name           string
	Namespace      string
	Type           string // Ingress or HTTPRoute
	DnsName        string
	TargetServices string
}
