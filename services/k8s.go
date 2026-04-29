package services

import (
	"context"
	"fmt"
	"strings"

	"servicetracker/models"

	"gorm.io/gorm"
	networkingv1 "k8s.io/api/networking/v1"
	k8serrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
)

// UpdateServerFromK8s reads the KubeConfig stored in the Server and fetches deployments, services, routes
func UpdateServerFromK8s(db *gorm.DB, serverID uint) error {
	var server models.Server
	if err := db.First(&server, serverID).Error; err != nil {
		return err
	}

	if server.KubeConfig == "" {
		return fmt.Errorf("server %s has no kubeconfig set", server.Name)
	}

	config, err := clientcmd.RESTConfigFromKubeConfig([]byte(server.KubeConfig))
	if err != nil {
		return err
	}

	workingConfig, err := configWithTLSFallback(config, &server)
	if err != nil {
		return err
	}

	clientset, err := kubernetes.NewForConfig(workingConfig)
	if err != nil {
		return err
	}

	dynamicClient, err := dynamic.NewForConfig(workingConfig)
	if err != nil {
		return err
	}

	// 1. Fetch Services & map Deployments
	svcList, err := clientset.CoreV1().Services("").List(context.TODO(), metav1.ListOptions{})
	if err != nil {
		return err
	}

	// Clear old data for server and recreate. For simplicity, we hard delete/recreate or just use Unscoped
	db.Where("server_id = ?", server.ID).Delete(&models.Service{})
	db.Where("server_id = ?", server.ID).Delete(&models.Route{})

	for _, svc := range svcList.Items {
		newSvc := models.Service{
			ServerID:  server.ID,
			Name:      svc.Name,
			Namespace: svc.Namespace,
			Type:      string(svc.Spec.Type),
		}
		db.Create(&newSvc)

		// Find associated deployments by matching selectors (simplified approach)
		deps, _ := clientset.AppsV1().Deployments(svc.Namespace).List(context.TODO(), metav1.ListOptions{})
		for _, dep := range deps.Items {
			// Naive matching: if deployment name contains service name or matches labels
			matched := false
			for k, v := range svc.Spec.Selector {
				if depValue, ok := dep.Spec.Template.Labels[k]; ok && depValue == v {
					matched = true
					break
				}
			}
			if matched {
				image := ""
				if len(dep.Spec.Template.Spec.Containers) > 0 {
					image = dep.Spec.Template.Spec.Containers[0].Image
				}

				replicas := 1
				if dep.Spec.Replicas != nil {
					replicas = int(*dep.Spec.Replicas)
				}

				newDep := models.Deployment{
					ServiceID:   newSvc.ID,
					Name:        dep.Name,
					Namespace:   dep.Namespace,
					DockerImage: image,
					Replicas:    replicas,
				}
				db.Create(&newDep)
			}
		}
	}

	// 2. Fetch Ingresses
	ingList, _ := clientset.NetworkingV1().Ingresses("").List(context.TODO(), metav1.ListOptions{})
	if ingList != nil {
		for _, ing := range ingList.Items {
			hosts := []string{}
			for _, rule := range ing.Spec.Rules {
				if rule.Host != "" {
					hosts = append(hosts, rule.Host)
				}
			}

			targetServices := collectIngressBackendServices(ing)

			if len(hosts) > 0 {
				newRoute := models.Route{
					ServerID:       server.ID,
					Name:           ing.Name,
					Namespace:      ing.Namespace,
					Type:           "Ingress",
					DnsName:        strings.Join(hosts, ", "),
					TargetServices: strings.Join(targetServices, ", "),
				}
				db.Create(&newRoute)
			}
		}
	}

	// 3. Fetch HTTPRoutes (Gateway API)
	if err := syncHTTPRoutes(dynamicClient, db, server.ID); err != nil {
		return err
	}

	return nil
}

func configWithTLSFallback(config *rest.Config, server *models.Server) (*rest.Config, error) {
	clientset, err := kubernetes.NewForConfig(config)
	if err != nil {
		return nil, err
	}

	if _, err := clientset.Discovery().ServerVersion(); err == nil {
		return rest.CopyConfig(config), nil
	} else {
		validNames, requestedName, ok := parseCertHostMismatch(err)
		if !ok {
			return nil, err
		}

		fallbackServerName, found := selectFallbackTLSServerName(validNames, requestedName, server)
		if !found {
			return nil, fmt.Errorf(
				"%w (certificate is valid for: %s; set the server IP/Overlay IP to a matching value, or update kubeconfig server URL)",
				err,
				strings.Join(validNames, ", "),
			)
		}

		retryConfig := rest.CopyConfig(config)
		retryConfig.TLSClientConfig.ServerName = fallbackServerName

		retryClientset, retryErr := kubernetes.NewForConfig(retryConfig)
		if retryErr != nil {
			return nil, retryErr
		}

		if _, retryErr = retryClientset.Discovery().ServerVersion(); retryErr != nil {
			return nil, retryErr
		}

		return retryConfig, nil
	}
}

func syncHTTPRoutes(dynamicClient dynamic.Interface, db *gorm.DB, serverID uint) error {
	versions := []string{"v1", "v1beta1"}

	for _, version := range versions {
		gvr := schema.GroupVersionResource{
			Group:    "gateway.networking.k8s.io",
			Version:  version,
			Resource: "httproutes",
		}

		routeList, err := dynamicClient.Resource(gvr).Namespace("").List(context.TODO(), metav1.ListOptions{})
		if err != nil {
			if isHTTPRouteAPINotAvailable(err) {
				continue
			}
			return err
		}

		for _, route := range routeList.Items {
			hostnames := extractHTTPRouteHostnames(route)
			targetServices := extractHTTPRouteBackendServices(route)
			newRoute := models.Route{
				ServerID:       serverID,
				Name:           route.GetName(),
				Namespace:      route.GetNamespace(),
				Type:           "HTTPRoute",
				DnsName:        strings.Join(hostnames, ", "),
				TargetServices: strings.Join(targetServices, ", "),
			}
			db.Create(&newRoute)
		}

		// Only one of the versions should exist; after successful list, stop trying others.
		return nil
	}

	// Gateway API is optional; no HTTPRoute CRD is not considered a sync failure.
	return nil
}

func extractHTTPRouteHostnames(route unstructured.Unstructured) []string {
	hostnames, found, _ := unstructured.NestedStringSlice(route.Object, "spec", "hostnames")
	if !found || len(hostnames) == 0 {
		return []string{}
	}
	return hostnames
}

func collectIngressBackendServices(ing networkingv1.Ingress) []string {
	services := []string{}
	seen := map[string]struct{}{}

	addService := func(namespace, name string) {
		name = strings.TrimSpace(name)
		namespace = strings.TrimSpace(namespace)
		if name == "" {
			return
		}
		if namespace == "" {
			namespace = ing.Namespace
		}

		serviceRef := formatServiceRef(namespace, name)
		if _, exists := seen[serviceRef]; exists {
			return
		}
		seen[serviceRef] = struct{}{}
		services = append(services, serviceRef)
	}

	if ing.Spec.DefaultBackend != nil && ing.Spec.DefaultBackend.Service != nil {
		addService(ing.Namespace, ing.Spec.DefaultBackend.Service.Name)
	}

	for _, rule := range ing.Spec.Rules {
		if rule.HTTP == nil {
			continue
		}

		for _, path := range rule.HTTP.Paths {
			if path.Backend.Service == nil {
				continue
			}
			addService(ing.Namespace, path.Backend.Service.Name)
		}
	}

	return services
}

func extractHTTPRouteBackendServices(route unstructured.Unstructured) []string {
	services := []string{}
	seen := map[string]struct{}{}

	addService := func(namespace, name string) {
		name = strings.TrimSpace(name)
		namespace = strings.TrimSpace(namespace)
		if name == "" {
			return
		}
		if namespace == "" {
			namespace = route.GetNamespace()
		}

		serviceRef := formatServiceRef(namespace, name)
		if _, exists := seen[serviceRef]; exists {
			return
		}
		seen[serviceRef] = struct{}{}
		services = append(services, serviceRef)
	}

	rules, found, _ := unstructured.NestedSlice(route.Object, "spec", "rules")
	if !found {
		return services
	}

	for _, ruleRaw := range rules {
		ruleMap, ok := ruleRaw.(map[string]interface{})
		if !ok {
			continue
		}

		backendRefsRaw, ok := ruleMap["backendRefs"].([]interface{})
		if !ok {
			continue
		}

		for _, backendRefRaw := range backendRefsRaw {
			backendRef, ok := backendRefRaw.(map[string]interface{})
			if !ok {
				continue
			}

			name, _ := backendRef["name"].(string)
			namespace, _ := backendRef["namespace"].(string)
			addService(namespace, name)
		}
	}

	return services
}

func formatServiceRef(namespace, name string) string {
	if namespace == "" {
		return name
	}
	return namespace + "/" + name
}

func isHTTPRouteAPINotAvailable(err error) bool {
	if k8serrors.IsNotFound(err) || k8serrors.IsMethodNotSupported(err) {
		return true
	}

	errMsg := strings.ToLower(err.Error())
	return strings.Contains(errMsg, "could not find the requested resource")
}

func parseCertHostMismatch(err error) ([]string, string, bool) {
	errMsg := err.Error()
	const marker = "x509: certificate is valid for "

	idx := strings.Index(errMsg, marker)
	if idx == -1 {
		return nil, "", false
	}

	tail := errMsg[idx+len(marker):]
	parts := strings.SplitN(tail, ", not ", 2)
	if len(parts) != 2 {
		return nil, "", false
	}

	requestedName := strings.TrimSpace(parts[1])
	rawValidNames := strings.Split(parts[0], ",")
	validNames := make([]string, 0, len(rawValidNames))
	for _, name := range rawValidNames {
		name = strings.TrimSpace(name)
		if name != "" {
			validNames = append(validNames, name)
		}
	}

	if len(validNames) == 0 || requestedName == "" {
		return nil, "", false
	}

	return validNames, requestedName, true
}

func selectFallbackTLSServerName(validNames []string, requestedName string, server *models.Server) (string, bool) {
	validLookup := make(map[string]struct{}, len(validNames))
	for _, validName := range validNames {
		validLookup[validName] = struct{}{}
	}

	candidates := []string{
		strings.TrimSpace(server.IP),
		strings.TrimSpace(server.OverlayIP),
	}

	seen := map[string]struct{}{}
	for _, candidate := range candidates {
		if candidate == "" || candidate == requestedName {
			continue
		}
		if _, alreadyChecked := seen[candidate]; alreadyChecked {
			continue
		}
		seen[candidate] = struct{}{}

		if _, ok := validLookup[candidate]; ok {
			return candidate, true
		}
	}

	return "", false
}
