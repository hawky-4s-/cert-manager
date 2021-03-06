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

// This file was automatically generated by informer-gen

package internalversion

import (
	certmanager "github.com/jetstack-experimental/cert-manager/pkg/apis/certmanager"
	internalclientset "github.com/jetstack-experimental/cert-manager/pkg/client/internalclientset"
	internalinterfaces "github.com/jetstack-experimental/cert-manager/pkg/informers/internalversion/internalinterfaces"
	internalversion "github.com/jetstack-experimental/cert-manager/pkg/listers/certmanager/internalversion"
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	runtime "k8s.io/apimachinery/pkg/runtime"
	watch "k8s.io/apimachinery/pkg/watch"
	cache "k8s.io/client-go/tools/cache"
	time "time"
)

// CertificateInformer provides access to a shared informer and lister for
// Certificates.
type CertificateInformer interface {
	Informer() cache.SharedIndexInformer
	Lister() internalversion.CertificateLister
}

type certificateInformer struct {
	factory internalinterfaces.SharedInformerFactory
}

func newCertificateInformer(client internalclientset.Interface, resyncPeriod time.Duration) cache.SharedIndexInformer {
	sharedIndexInformer := cache.NewSharedIndexInformer(
		&cache.ListWatch{
			ListFunc: func(options v1.ListOptions) (runtime.Object, error) {
				return client.Certmanager().Certificates(v1.NamespaceAll).List(options)
			},
			WatchFunc: func(options v1.ListOptions) (watch.Interface, error) {
				return client.Certmanager().Certificates(v1.NamespaceAll).Watch(options)
			},
		},
		&certmanager.Certificate{},
		resyncPeriod,
		cache.Indexers{cache.NamespaceIndex: cache.MetaNamespaceIndexFunc},
	)

	return sharedIndexInformer
}

func (f *certificateInformer) Informer() cache.SharedIndexInformer {
	return f.factory.InformerFor(&certmanager.Certificate{}, newCertificateInformer)
}

func (f *certificateInformer) Lister() internalversion.CertificateLister {
	return internalversion.NewCertificateLister(f.Informer().GetIndexer())
}
