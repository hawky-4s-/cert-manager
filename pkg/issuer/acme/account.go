package acme

import (
	"context"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"strings"

	"golang.org/x/crypto/acme"
	api "k8s.io/api/core/v1"
	k8sErrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	corev1listers "k8s.io/client-go/listers/core/v1"

	"github.com/jetstack-experimental/cert-manager/pkg/apis/certmanager/v1alpha1"
	"github.com/jetstack-experimental/cert-manager/pkg/log"
	"github.com/jetstack-experimental/cert-manager/pkg/util"
)

const (
	acmeAccountPrivateKeyKey = "key.pem"
)

type account struct {
	issuer *v1alpha1.Issuer

	client        kubernetes.Interface
	secretsLister corev1listers.SecretLister
}

func newAccount(issuer *v1alpha1.Issuer, client kubernetes.Interface, secretsLister corev1listers.SecretLister) *account {
	return &account{issuer, client, secretsLister}
}

func (a *account) uri() string {
	if a.issuer.Status.ACME == nil {
		return ""
	}
	return a.issuer.Status.ACME.URI
}

func (a *account) email() string {
	if a.issuer.Spec.ACME == nil {
		return ""
	}
	return a.issuer.Spec.ACME.Email
}

func (a *account) server() string {
	if a.issuer.Spec.ACME == nil {
		return ""
	}
	return a.issuer.Spec.ACME.Server
}

// privateKey returns the private key for this account from the given context,
// or an error
// TODO (@munnerz): how can we support different types of private keys other
// than rsa?
func (a *account) privateKey() (*rsa.PrivateKey, error) {
	if a.issuer.Spec.ACME == nil {
		return nil, fmt.Errorf("acme spec block cannot be empty")
	}

	keyName := a.issuer.Spec.ACME.PrivateKey
	keySecret, err := a.secretsLister.Secrets(a.issuer.Namespace).Get(keyName)

	if err != nil {
		// we return the plain error here so k8sErrors.IsNotFound can be used
		return nil, err
	}

	keyBytes, okkey := keySecret.Data[acmeAccountPrivateKeyKey]

	// TODO: should we automatically recover from this situation by creating the key?
	if !okkey {
		return nil, fmt.Errorf("no '%s' key set in account secret", api.TLSPrivateKeyKey)
	}

	// decode the private key pem
	block, _ := pem.Decode(keyBytes)
	if block == nil {
		return nil, fmt.Errorf("error decoding private key PEM block in '%s'", keyName)
	}
	// parse the private key
	key, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("error parsing private key in '%s': %s", keyName, err.Error())
	}
	// validate the private key
	if err = key.Validate(); err != nil {
		return nil, fmt.Errorf("private key failed validation in '%s': %s", keyName, err.Error())
	}

	return key, nil
}

// verify verifies an acme account is valid with the acme server
func (a *account) verify() error {
	if a.issuer.Spec.ACME.Server == "" {
		return fmt.Errorf("acme server url must be set")
	}
	if a.issuer.Status.ACME == nil || a.issuer.Status.ACME.URI == "" {
		return fmt.Errorf("acme account uri must be set")
	}

	privateKey, err := a.privateKey()

	if err != nil {
		a.issuer.Status.Ready = false
		return err
	}

	log.Printf("using acme server '%s' for verification", a.issuer.Spec.ACME.Server)
	cl := acme.Client{
		Key:          privateKey,
		DirectoryURL: a.issuer.Spec.ACME.Server,
	}

	_, err = cl.GetReg(context.Background(), a.issuer.Status.ACME.URI)

	if err != nil {
		return fmt.Errorf("error getting acme registration: %s", err.Error())
	}

	// TODO: come up with some way to verify the private key is valid for this
	// account

	return nil
}

// register will register an account with the acme server and store the account
// details in the context
// TODO: break this function down
func (a *account) register() error {
	if a.issuer.Spec.ACME.Server == "" {
		return fmt.Errorf("acme server url must be set")
	}

	privateKey, err := a.privateKey()
	var privateKeyPem []byte
	if err != nil {
		if !k8sErrors.IsNotFound(err) {
			return fmt.Errorf("error getting private key: %s", err.Error())
		}

		// TODO (@munnerz): allow changing the keysize
		privateKeyPem, privateKey, err = generatePrivateKey(2048)

		if err != nil {
			return fmt.Errorf("error generating private key: %s", err.Error())
		}

		_, err = util.EnsureSecret(a.client, &api.Secret{
			ObjectMeta: metav1.ObjectMeta{
				Name:      a.issuer.Spec.ACME.PrivateKey,
				Namespace: a.issuer.Namespace,
			},
			Data: map[string][]byte{
				acmeAccountPrivateKeyKey: privateKeyPem,
			},
		})

		if err != nil {
			return fmt.Errorf("error saving private key: %s", err.Error())
		}
	}

	log.Printf("using acme server '%s' for registration", a.issuer.Spec.ACME.Server)
	cl := acme.Client{
		Key:          privateKey,
		DirectoryURL: a.issuer.Spec.ACME.Server,
	}

	acc := &acme.Account{
		Contact: []string{fmt.Sprintf("mailto:%s", strings.ToLower(a.issuer.Spec.ACME.Email))},
	}

	// todo (@munnerz): don't use ctx.Background() here
	account, err := cl.Register(context.Background(), acc, acme.AcceptTOS)

	if err != nil {
		var acmeErr *acme.Error
		var ok bool
		if acmeErr, ok = err.(*acme.Error); !ok || (acmeErr.StatusCode != 409) {
			return fmt.Errorf("error registering acme account: %s", err.Error())
		}

		if a.issuer.Status.ACME == nil || a.issuer.Status.ACME.URI == "" {
			return fmt.Errorf("private key already registered but user URI not found. delete existing private key or set acme account URI")
		}

		if account, err = cl.UpdateReg(context.Background(), acc); err != nil {
			return fmt.Errorf("error updating acme account registration: %s", err.Error())
		}
	}

	a.issuer.Status.ACMEStatus().URI = account.URI

	return nil
}
