/*
Copyright 2017 The Kubernetes Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"time"

	corev1 "k8s.io/api/core/v1"
	apiextensionsclient "k8s.io/apiextensions-apiserver/pkg/client/clientset/clientset"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/informers"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/kubernetes/scheme"
	corev1client "k8s.io/client-go/kubernetes/typed/core/v1"
	_ "k8s.io/client-go/plugin/pkg/client/auth"
	rest "k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
	"k8s.io/client-go/tools/leaderelection"
	"k8s.io/client-go/tools/leaderelection/resourcelock"
	"k8s.io/client-go/tools/record"

	_ "github.com/jetstack-experimental/cert-manager/pkg/apis/certmanager/install"
	"github.com/jetstack-experimental/cert-manager/pkg/client"
	"github.com/jetstack-experimental/cert-manager/pkg/controller"
	"github.com/jetstack-experimental/cert-manager/pkg/controller/certificates"
	"github.com/jetstack-experimental/cert-manager/pkg/controller/issuers"
	"github.com/jetstack-experimental/cert-manager/pkg/informers/externalversions"
	"github.com/jetstack-experimental/cert-manager/pkg/issuer"
	_ "github.com/jetstack-experimental/cert-manager/pkg/issuer/acme"
	logpkg "github.com/jetstack-experimental/cert-manager/pkg/log"
)

const (
	agentName = "cert-manager-controller"
)

var (
	apiServerHost = flag.String("apiserver", "", "optional API server host address")
	namespace     = flag.String("namespace", "", "optional namespace to operate within")
	podNamespace  = flag.String("pod-namespace", "", "the namespace the cert-manager pod runs within")
)

func main() {
	flag.Parse()
	log := logpkg.Default()

	cfg, err := kubeConfig(*apiServerHost)

	if err != nil {
		log.Fatalf("error getting in-cluster config: %s", err.Error())
	}

	cl, err := kubernetes.NewForConfig(cfg)

	if err != nil {
		log.Fatalf("error creating kubernetes clientset: %s", err.Error())
	}

	eventBroadcaster := record.NewBroadcaster()
	eventBroadcaster.StartLogging(log.Printf)
	eventBroadcaster.StartRecordingToSink(&corev1client.EventSinkImpl{Interface: cl.Core().Events("")})
	recorder := eventBroadcaster.NewRecorder(scheme.Scheme, corev1.EventSource{Component: agentName})

	id, err := os.Hostname()
	if err != nil {
		log.Fatalf("error getting hostname: %s", err.Error())
	}

	stopCh := make(chan struct{})
	le, err := leaderelection.NewLeaderElector(leaderelection.LeaderElectionConfig{
		Lock: &resourcelock.EndpointsLock{
			EndpointsMeta: metav1.ObjectMeta{
				Namespace: *podNamespace,
				Name:      "cert-manager",
			},
			Client: cl.CoreV1(),
			LockConfig: resourcelock.ResourceLockConfig{
				Identity:      id + "-external-cert-manager",
				EventRecorder: recorder,
			},
		},
		LeaseDuration: 60 * time.Second,
		RenewDeadline: 30 * time.Second,
		RetryPeriod:   5 * time.Second,
		Callbacks: leaderelection.LeaderCallbacks{
			OnStartedLeading: func(stop <-chan struct{}) {
				go func() {
					defer close(stopCh)
					<-stop
				}()
				start(cfg, cl, stopCh)
			},
			OnStoppedLeading: func() {
				log.Printf("lost leadership lock. signalling workers to exit...")
				close(stopCh)
				log.Printf("workers drained. exiting...")
				os.Exit(0)
			},
		},
	})
	if err != nil {
		log.Fatalf(err.Error())
	}
	le.Run()
}

func start(cfg *rest.Config, cl kubernetes.Interface, stopCh <-chan struct{}) {
	if err := registerCRDResources(cfg); err != nil {
		log.Fatalf("error registering custom resource definition with API server: %s", err.Error())
	}

	cmCl, err := client.NewForConfig(cfg)

	if err != nil {
		log.Fatalf("error creating cert-manager clientset: %s", err.Error())
	}

	factory := informers.NewSharedInformerFactory(cl, time.Second*30)
	cmFactory := externalversions.NewSharedInformerFactory(cmCl, time.Second*30)

	issuer.SharedFactory().Setup(cl, cmCl, factory, cmFactory)
	controller.SharedFactory().Setup(cl, cmCl, factory, cmFactory)

	issuerCtrl, err := controller.SharedFactory().Controller(issuers.ControllerName)
	if err != nil {
		log.Fatalf(err.Error())
	}

	certificateCtrl, err := controller.SharedFactory().Controller(certificates.ControllerName)
	if err != nil {
		log.Fatalf(err.Error())
	}

	factory.Start(stopCh)
	cmFactory.Start(stopCh)

	go issuerCtrl.Run(5, stopCh)
	go certificateCtrl.Run(5, stopCh)

	<-stopCh
}

// kubeConfig will return a rest.Config for communicating with the Kubernetes API server.
// If apiServerHost is specified, a config without authentication that is configured
// to talk to the apiServerHost URL will be returned. Else, the in-cluster config will be loaded,
// and failing this, the config will be loaded from the users local kubeconfig directory
func kubeConfig(apiServerHost string) (*rest.Config, error) {
	var err error
	var cfg *rest.Config

	if len(apiServerHost) > 0 {
		cfg = new(rest.Config)
		cfg.Host = apiServerHost
	} else if cfg, err = rest.InClusterConfig(); err != nil {
		apiCfg, err := clientcmd.NewDefaultClientConfigLoadingRules().Load()

		if err != nil {
			return nil, fmt.Errorf("error loading cluster config: %s", err.Error())
		}

		cfg, err = clientcmd.NewDefaultClientConfig(*apiCfg, &clientcmd.ConfigOverrides{}).ClientConfig()

		if err != nil {
			return nil, fmt.Errorf("error loading cluster client config: %s", err.Error())
		}
	}

	return cfg, nil
}

func registerCRDResources(config *rest.Config) error {
	apiextensionsclientset, err := apiextensionsclient.NewForConfig(config)
	if err != nil {
		return err
	}

	if _, err := CreateCustomResourceDefinition(apiextensionsclientset, "certificates.certmanager.k8s.io", "certmanager.k8s.io", "v1alpha1", "certificates", "Certificate"); err != nil {
		return err
	}

	if _, err := CreateCustomResourceDefinition(apiextensionsclientset, "issuers.certmanager.k8s.io", "certmanager.k8s.io", "v1alpha1", "issuers", "Issuer"); err != nil {
		return err
	}

	return nil
}
