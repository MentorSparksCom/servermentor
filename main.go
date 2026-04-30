package main

import (
	"fmt"
	"html/template"
	"io/fs"
	"log"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"servicetracker/models"
	"servicetracker/services"

	"github.com/gin-gonic/gin"
	"github.com/joho/godotenv"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
)

var (
	authManager *AuthManager
	db          *gorm.DB
)

func init() {
	if err := godotenv.Load(); err != nil {
		log.Println("No .env file found")
	}

	dsn := fmt.Sprintf("host=%s user=%s password=%s dbname=%s port=%s sslmode=disable TimeZone=UTC",
		os.Getenv("DB_HOST"), os.Getenv("DB_USER"), os.Getenv("DB_PASSWORD"),
		os.Getenv("DB_NAME"), os.Getenv("DB_PORT"))

	var err error
	db, err = gorm.Open(postgres.Open(dsn), &gorm.Config{})
	if err != nil {
		log.Fatal("Failed to connect to database:", err)
	}

	db.AutoMigrate(&models.Server{}, &models.Service{}, &models.Deployment{}, &models.Route{})

	authManager, err = NewAuthManagerFromEnv()
	if err != nil {
		log.Fatal("Failed to initialize auth:", err)
	}
}

func main() {
	r := gin.Default()

	loadTemplates(r)
	r.Static("/static", "./static")

	r.GET("/", authManager.ShowLogin)
	r.GET("/logout", authManager.Logout)
	r.GET("/auth/:provider/login", authManager.HandleLogin)
	r.GET("/auth/:provider/callback", authManager.HandleCallback)
	r.GET("/login/oauth2/code/mentorlogin", authManager.HandleCallbackFor("mentorlogin"))

	admin := r.Group("/admin")
	admin.Use(authManager.RequireAdmin())
	{
		admin.GET("/", adminDashboard)
		admin.GET("/servers", adminServers)
		admin.GET("/services", adminServicesGlobal)
		admin.GET("/routes", adminRoutesGlobal)
		admin.GET("/servers/new", adminServerNew)
		admin.GET("/servers/:id", adminServerOverview)
		admin.GET("/servers/:id/edit", adminServerEdit)
		admin.GET("/servers/:id/services", adminServerServices)
		admin.GET("/servers/:id/deployments", adminServerDeployments)
		admin.GET("/servers/:id/routes", adminServerRoutes)
		admin.GET("/servers/:id/dns", adminServerDNS)
		admin.POST("/servers", createServer)
		admin.POST("/servers/:id/edit", updateServer)
		admin.POST("/servers/:id/sync", syncK8s) // "press a button in admin"
		admin.POST("/servers/:id/delete", deleteServer)
	}

	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}
	r.Run(":" + port)
}

func loadTemplates(r *gin.Engine) {
	tmpl := template.New("").Funcs(template.FuncMap{
		"splitCSV":           splitCSV,
		"serviceFilterQuery": serviceFilterQuery,
	})
	err := filepath.WalkDir("templates", func(path string, d fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if d.IsDir() || !strings.HasSuffix(path, ".html") {
			return nil
		}

		var parseErr error
		tmpl, parseErr = tmpl.ParseFiles(path)
		return parseErr
	})
	if err != nil {
		log.Fatal("failed to parse templates:", err)
	}

	r.SetHTMLTemplate(tmpl)
}

func splitCSV(value string) []string {
	parts := strings.Split(value, ",")
	cleaned := make([]string, 0, len(parts))
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part != "" {
			cleaned = append(cleaned, part)
		}
	}
	return cleaned
}

func serviceFilterQuery(serviceRef string) string {
	serviceRef = strings.TrimSpace(serviceRef)
	namespace, service := parseServiceRef(serviceRef)
	values := url.Values{}
	if serviceRef != "" {
		values.Set("serviceRef", serviceRef)
	}
	if service != "" {
		values.Set("service", service)
	}
	if namespace != "" {
		values.Set("namespace", namespace)
	}
	return values.Encode()
}

func parseServiceRef(serviceRef string) (string, string) {
	serviceRef = strings.TrimSpace(serviceRef)
	if serviceRef == "" {
		return "", ""
	}

	parts := strings.SplitN(serviceRef, "/", 2)
	if len(parts) == 2 {
		return strings.TrimSpace(parts[0]), strings.TrimSpace(parts[1])
	}

	return "", serviceRef
}

func adminDashboard(c *gin.Context) {
	var servers []models.Server
	db.Preload("Services").Preload("Routes").Find(&servers)

	serviceCount := 0
	routeCount := 0
	for _, s := range servers {
		serviceCount += len(s.Services)
		routeCount += len(s.Routes)
	}

	c.HTML(http.StatusOK, "dashboard.html", gin.H{
		"Servers":      servers,
		"ServerCount":  len(servers),
		"ServiceCount": serviceCount,
		"RouteCount":   routeCount,
		"PageTitle":    "Dashboard",
		"ActiveNav":    "dashboard",
	})
}

func adminServers(c *gin.Context) {
	nameFilter := strings.TrimSpace(c.Query("name"))
	providerFilter := strings.TrimSpace(c.Query("provider"))
	ipFilter := strings.TrimSpace(c.Query("ip"))
	overlayIPFilter := strings.TrimSpace(c.Query("overlayIp"))
	tagsFilter := strings.TrimSpace(c.Query("tags"))

	query := db.Model(&models.Server{})
	if nameFilter != "" {
		query = query.Where("name ILIKE ?", "%"+nameFilter+"%")
	}
	if providerFilter != "" {
		query = query.Where("provider ILIKE ?", "%"+providerFilter+"%")
	}
	if ipFilter != "" {
		query = query.Where("ip ILIKE ?", "%"+ipFilter+"%")
	}
	if overlayIPFilter != "" {
		query = query.Where("overlay_ip ILIKE ?", "%"+overlayIPFilter+"%")
	}
	if tagsFilter != "" {
		query = query.Where("tags ILIKE ?", "%"+tagsFilter+"%")
	}

	var servers []models.Server
	if err := query.Preload("Services").Preload("Routes").Order("name ASC").Find(&servers).Error; err != nil {
		c.String(http.StatusInternalServerError, "Failed to load servers: "+err.Error())
		return
	}

	// flash after delete
	deletedName := c.Query("deleted")
	c.HTML(http.StatusOK, "servers.html", gin.H{
		"Servers":         servers,
		"DeletedName":     deletedName,
		"NameFilter":      nameFilter,
		"ProviderFilter":  providerFilter,
		"IPFilter":        ipFilter,
		"OverlayIPFilter": overlayIPFilter,
		"TagsFilter":      tagsFilter,
		"PageTitle":       "Servers",
		"ActiveNav":       "servers",
	})
}

type globalServiceListItem struct {
	ID              uint
	ServerID        uint
	ServerName      string
	Name            string
	Namespace       string
	Type            string
	DeploymentCount int64
}

func adminServicesGlobal(c *gin.Context) {
	serverFilter := strings.TrimSpace(c.Query("server"))
	nameFilter := strings.TrimSpace(c.Query("name"))
	namespaceFilter := strings.TrimSpace(c.Query("namespace"))
	typeFilter := strings.TrimSpace(c.Query("type"))
	deploymentFilter := strings.TrimSpace(c.Query("deployment"))

	query := db.Table("services").
		Select("services.id, services.server_id, servers.name as server_name, services.name, services.namespace, services.type, COUNT(deployments.id) as deployment_count").
		Joins("JOIN servers ON servers.id = services.server_id").
		Joins("LEFT JOIN deployments ON deployments.service_id = services.id AND deployments.deleted_at IS NULL").
		Where("services.deleted_at IS NULL")

	if serverFilter != "" {
		query = query.Where("servers.name ILIKE ?", "%"+serverFilter+"%")
	}
	if nameFilter != "" {
		query = query.Where("services.name ILIKE ?", "%"+nameFilter+"%")
	}
	if namespaceFilter != "" {
		query = query.Where("services.namespace ILIKE ?", "%"+namespaceFilter+"%")
	}
	if typeFilter != "" {
		query = query.Where("services.type ILIKE ?", "%"+typeFilter+"%")
	}
	if deploymentFilter != "" {
		query = query.Where("deployments.name ILIKE ?", "%"+deploymentFilter+"%")
	}

	var services []globalServiceListItem
	if err := query.
		Group("services.id, services.server_id, servers.name, services.name, services.namespace, services.type").
		Order("servers.name ASC, services.namespace ASC, services.name ASC").
		Scan(&services).Error; err != nil {
		c.String(http.StatusInternalServerError, "Failed to load services: "+err.Error())
		return
	}

	c.HTML(http.StatusOK, "services.html", gin.H{
		"Services":         services,
		"ServerFilter":     serverFilter,
		"NameFilter":       nameFilter,
		"NamespaceFilter":  namespaceFilter,
		"TypeFilter":       typeFilter,
		"DeploymentFilter": deploymentFilter,
		"PageTitle":        "Services",
		"ActiveNav":        "services",
	})
}

type globalRouteListItem struct {
	ID             uint
	ServerID       uint
	ServerName     string
	Name           string
	Namespace      string
	Type           string
	DnsName        string
	TargetServices string
}

func adminRoutesGlobal(c *gin.Context) {
	serverFilter := strings.TrimSpace(c.Query("server"))
	nameFilter := strings.TrimSpace(c.Query("name"))
	namespaceFilter := strings.TrimSpace(c.Query("namespace"))
	typeFilter := strings.TrimSpace(c.Query("type"))
	dnsFilter := strings.TrimSpace(c.Query("dns"))
	targetFilter := strings.TrimSpace(c.Query("target"))

	query := db.Table("routes").
		Select("routes.id, routes.server_id, servers.name as server_name, routes.name, routes.namespace, routes.type, routes.dns_name, routes.target_services").
		Joins("JOIN servers ON servers.id = routes.server_id").
		Where("routes.deleted_at IS NULL")

	if serverFilter != "" {
		query = query.Where("servers.name ILIKE ?", "%"+serverFilter+"%")
	}
	if nameFilter != "" {
		query = query.Where("routes.name ILIKE ?", "%"+nameFilter+"%")
	}
	if namespaceFilter != "" {
		query = query.Where("routes.namespace ILIKE ?", "%"+namespaceFilter+"%")
	}
	if typeFilter != "" {
		query = query.Where("routes.type ILIKE ?", "%"+typeFilter+"%")
	}
	if dnsFilter != "" {
		query = query.Where("routes.dns_name ILIKE ?", "%"+dnsFilter+"%")
	}
	if targetFilter != "" {
		query = query.Where("routes.target_services ILIKE ?", "%"+targetFilter+"%")
	}

	var routes []globalRouteListItem
	if err := query.
		Order("servers.name ASC, routes.namespace ASC, routes.name ASC").
		Scan(&routes).Error; err != nil {
		c.String(http.StatusInternalServerError, "Failed to load routes: "+err.Error())
		return
	}

	c.HTML(http.StatusOK, "routes.html", gin.H{
		"Routes":          routes,
		"ServerFilter":    serverFilter,
		"NameFilter":      nameFilter,
		"NamespaceFilter": namespaceFilter,
		"TypeFilter":      typeFilter,
		"DNSFilter":       dnsFilter,
		"TargetFilter":    targetFilter,
		"PageTitle":       "Routes",
		"ActiveNav":       "routes",
	})
}

func adminServerNew(c *gin.Context) {
	c.HTML(http.StatusOK, "server_new.html", gin.H{
		"PageTitle": "New Server",
		"ActiveNav": "servers",
	})
}

func createServer(c *gin.Context) {
	name := c.PostForm("name")
	provider := c.PostForm("provider")
	ip := c.PostForm("ip")
	overlayIP := c.PostForm("overlayIp")
	ram := c.PostForm("ram")
	diskSize := c.PostForm("diskSize")
	tags := c.PostForm("tags")
	kubeConfig := c.PostForm("kubeConfig")

	db.Create(&models.Server{
		Name:       name,
		Provider:   provider,
		IP:         ip,
		OverlayIP:  overlayIP,
		RAM:        ram,
		DiskSize:   diskSize,
		Tags:       tags,
		KubeConfig: kubeConfig,
	})

	c.Redirect(http.StatusFound, "/admin/servers")
}

func loadServerForAdmin(c *gin.Context) (*models.Server, bool) {
	serverID := c.Param("id")
	var server models.Server
	err := db.Preload("Services").Preload("Services.Deployments").Preload("Routes").First(&server, serverID).Error
	if err != nil {
		c.String(http.StatusNotFound, "Server not found")
		return nil, false
	}

	return &server, true
}

func adminServerOverview(c *gin.Context) {
	server, ok := loadServerForAdmin(c)
	if !ok {
		return
	}

	// pass delete error/success messages back to template if present
	deleteError := c.Query("deleteError")
	deleteMessage := c.Query("msg")

	c.HTML(http.StatusOK, "server_overview.html", gin.H{
		"Server":        server,
		"DeleteError":   deleteError,
		"DeleteMessage": deleteMessage,
		"PageTitle":     "Server Overview",
		"ActiveNav":     "servers",
		"ServerSubNav":  "overview",
	})
}

func adminServerEdit(c *gin.Context) {
	server, ok := loadServerForAdmin(c)
	if !ok {
		return
	}

	c.HTML(http.StatusOK, "server_edit.html", gin.H{
		"Server":       server,
		"PageTitle":    "Edit Server",
		"ActiveNav":    "servers",
		"ServerSubNav": "overview",
	})
}

func updateServer(c *gin.Context) {
	server, ok := loadServerForAdmin(c)
	if !ok {
		return
	}

	server.Name = c.PostForm("name")
	server.Provider = c.PostForm("provider")
	server.IP = c.PostForm("ip")
	server.OverlayIP = c.PostForm("overlayIp")
	server.RAM = c.PostForm("ram")
	server.DiskSize = c.PostForm("diskSize")
	server.Tags = c.PostForm("tags")
	server.KubeConfig = c.PostForm("kubeConfig")

	if err := db.Save(server).Error; err != nil {
		c.String(http.StatusInternalServerError, "Failed to update server: "+err.Error())
		return
	}

	c.Redirect(http.StatusFound, "/admin/servers/"+c.Param("id"))
}

func adminServerServices(c *gin.Context) {
	server, ok := loadServerForAdmin(c)
	if !ok {
		return
	}

	serviceRefFilter := strings.TrimSpace(c.Query("serviceRef"))
	serviceFilter := strings.TrimSpace(c.Query("service"))
	namespaceFilter := strings.TrimSpace(c.Query("namespace"))
	typeFilter := strings.TrimSpace(c.Query("type"))
	deploymentFilter := strings.TrimSpace(c.Query("deployment"))

	if serviceRefFilter != "" {
		refNamespace, refService := parseServiceRef(serviceRefFilter)
		if serviceFilter == "" {
			serviceFilter = refService
		}
		if namespaceFilter == "" {
			namespaceFilter = refNamespace
		}
	}

	if strings.Contains(serviceFilter, "/") {
		refNamespace, refService := parseServiceRef(serviceFilter)
		if refService != "" {
			serviceFilter = refService
		}
		if namespaceFilter == "" {
			namespaceFilter = refNamespace
		}
	}

	if serviceRefFilter != "" || serviceFilter != "" || namespaceFilter != "" || typeFilter != "" || deploymentFilter != "" {
		filtered := make([]models.Service, 0, len(server.Services))
		for _, svc := range server.Services {
			serviceRef := composeServiceRef(svc.Namespace, svc.Name)

			if serviceRefFilter != "" && !strings.EqualFold(serviceRef, serviceRefFilter) {
				continue
			}

			if serviceFilter != "" && !containsFold(svc.Name, serviceFilter) {
				continue
			}
			if namespaceFilter != "" && !containsFold(svc.Namespace, namespaceFilter) {
				continue
			}
			if typeFilter != "" && !containsFold(svc.Type, typeFilter) {
				continue
			}
			if deploymentFilter != "" {
				matchDep := false
				for _, dep := range svc.Deployments {
					if containsFold(dep.Name, deploymentFilter) {
						matchDep = true
						break
					}
				}
				if !matchDep {
					continue
				}
			}
			filtered = append(filtered, svc)
		}
		server.Services = filtered
	}

	c.HTML(http.StatusOK, "server_services.html", gin.H{
		"Server":           server,
		"ServiceFilter":    serviceFilter,
		"NamespaceFilter":  namespaceFilter,
		"TypeFilter":       typeFilter,
		"DeploymentFilter": deploymentFilter,
		"PageTitle":        "Server Services",
		"ActiveNav":        "servers",
		"ServerSubNav":     "services",
	})
}

func composeServiceRef(namespace, name string) string {
	namespace = strings.TrimSpace(namespace)
	name = strings.TrimSpace(name)
	if namespace == "" {
		return name
	}
	return namespace + "/" + name
}

func adminServerDeployments(c *gin.Context) {
	server, ok := loadServerForAdmin(c)
	if !ok {
		return
	}

	deploymentFilter := strings.TrimSpace(c.Query("deployment"))
	namespaceFilter := strings.TrimSpace(c.Query("namespace"))

	deployments := make([]models.Deployment, 0)
	for _, svc := range server.Services {
		deployments = append(deployments, svc.Deployments...)
	}

	if deploymentFilter != "" || namespaceFilter != "" {
		filtered := make([]models.Deployment, 0, len(deployments))
		for _, dep := range deployments {
			if deploymentFilter != "" && !strings.EqualFold(dep.Name, deploymentFilter) {
				continue
			}
			if namespaceFilter != "" && !strings.EqualFold(dep.Namespace, namespaceFilter) {
				continue
			}
			filtered = append(filtered, dep)
		}
		deployments = filtered
	}

	c.HTML(http.StatusOK, "server_deployments.html", gin.H{
		"Server":           server,
		"Deployments":      deployments,
		"DeploymentFilter": deploymentFilter,
		"NamespaceFilter":  namespaceFilter,
		"PageTitle":        "Server Deployments",
		"ActiveNav":        "servers",
		"ServerSubNav":     "deployments",
	})
}

func adminServerRoutes(c *gin.Context) {
	server, ok := loadServerForAdmin(c)
	if !ok {
		return
	}

	nameFilter := strings.TrimSpace(c.Query("name"))
	namespaceFilter := strings.TrimSpace(c.Query("namespace"))
	typeFilter := strings.TrimSpace(c.Query("type"))
	dnsFilter := strings.TrimSpace(c.Query("dns"))
	targetFilter := strings.TrimSpace(c.Query("target"))

	if nameFilter != "" || namespaceFilter != "" || typeFilter != "" || dnsFilter != "" || targetFilter != "" {
		filtered := make([]models.Route, 0, len(server.Routes))
		for _, route := range server.Routes {
			if nameFilter != "" && !containsFold(route.Name, nameFilter) {
				continue
			}
			if namespaceFilter != "" && !containsFold(route.Namespace, namespaceFilter) {
				continue
			}
			if typeFilter != "" && !containsFold(route.Type, typeFilter) {
				continue
			}
			if dnsFilter != "" && !containsFold(route.DnsName, dnsFilter) {
				continue
			}
			if targetFilter != "" && !containsFold(route.TargetServices, targetFilter) {
				continue
			}
			filtered = append(filtered, route)
		}
		server.Routes = filtered
	}

	c.HTML(http.StatusOK, "server_routes.html", gin.H{
		"Server":          server,
		"NameFilter":      nameFilter,
		"NamespaceFilter": namespaceFilter,
		"TypeFilter":      typeFilter,
		"DNSFilter":       dnsFilter,
		"TargetFilter":    targetFilter,
		"PageTitle":       "Server Routes",
		"ActiveNav":       "servers",
		"ServerSubNav":    "routes",
	})
}

func containsFold(value string, filter string) bool {
	value = strings.ToLower(strings.TrimSpace(value))
	filter = strings.ToLower(strings.TrimSpace(filter))

	if filter == "" {
		return true
	}

	return strings.Contains(value, filter)
}

func routeDNSNames(routes []models.Route) []string {
	seen := make(map[string]struct{}, len(routes))
	names := make([]string, 0, len(routes))

	for _, route := range routes {
		name := strings.TrimSpace(route.DnsName)
		if name == "" {
			continue
		}

		key := strings.ToLower(name)
		if _, exists := seen[key]; exists {
			continue
		}

		seen[key] = struct{}{}
		names = append(names, name)
	}

	sort.Strings(names)
	return names
}

func adminServerDNS(c *gin.Context) {
	server, ok := loadServerForAdmin(c)
	if !ok {
		return
	}

	dnsNames := routeDNSNames(server.Routes)

	c.HTML(http.StatusOK, "server_dns.html", gin.H{
		"Server":       server,
		"DNSNames":     dnsNames,
		"PageTitle":    "Server DNS",
		"ActiveNav":    "servers",
		"ServerSubNav": "dns",
	})
}

func syncK8s(c *gin.Context) {
	serverID := c.Param("id")
	var server models.Server
	db.First(&server, serverID)

	err := services.UpdateServerFromK8s(db, server.ID)
	if err != nil {
		c.String(http.StatusInternalServerError, "Failed to sync Kubernetes info: "+err.Error())
		return
	}

	c.Redirect(http.StatusFound, "/admin/servers")
}

// deleteServer handles deletion of a server and its child records (deployments, services, routes)
func deleteServer(c *gin.Context) {
	serverID := c.Param("id")
	var server models.Server
	if err := db.First(&server, serverID).Error; err != nil {
		c.String(http.StatusNotFound, "Server not found")
		return
	}

	confirm := c.PostForm("confirm_name")
	if strings.TrimSpace(confirm) != strings.TrimSpace(server.Name) {
		// redirect back to overview with an error
		msg := url.QueryEscape("confirmation name does not match")
		c.Redirect(http.StatusFound, "/admin/servers/"+serverID+"?deleteError=1&msg="+msg)
		return
	}

	tx := db.Begin()
	// gather service ids
	var svcs []models.Service
	if err := tx.Select("id").Where("server_id = ?", server.ID).Find(&svcs).Error; err != nil {
		tx.Rollback()
		c.String(http.StatusInternalServerError, "Failed to query services: "+err.Error())
		return
	}

	ids := make([]uint, 0, len(svcs))
	for _, s := range svcs {
		ids = append(ids, s.ID)
	}

	if len(ids) > 0 {
		if err := tx.Where("service_id IN ?", ids).Delete(&models.Deployment{}).Error; err != nil {
			tx.Rollback()
			c.String(http.StatusInternalServerError, "Failed to delete deployments: "+err.Error())
			return
		}
	}

	if err := tx.Where("server_id = ?", server.ID).Delete(&models.Service{}).Error; err != nil {
		tx.Rollback()
		c.String(http.StatusInternalServerError, "Failed to delete services: "+err.Error())
		return
	}

	if err := tx.Where("server_id = ?", server.ID).Delete(&models.Route{}).Error; err != nil {
		tx.Rollback()
		c.String(http.StatusInternalServerError, "Failed to delete routes: "+err.Error())
		return
	}

	if err := tx.Delete(&server).Error; err != nil {
		tx.Rollback()
		c.String(http.StatusInternalServerError, "Failed to delete server: "+err.Error())
		return
	}

	if err := tx.Commit().Error; err != nil {
		c.String(http.StatusInternalServerError, "Failed to commit deletion: "+err.Error())
		return
	}

	c.Redirect(http.StatusFound, "/admin/servers?deleted="+url.QueryEscape(server.Name))
}
