package certutils

import (
	"context"
	"crypto/md5"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"log"
	"strings"
	"sync"
	"time"

	"github.com/go-acme/lego/v4/certcrypto"
	"github.com/go-acme/lego/v4/certificate"
	"github.com/go-acme/lego/v4/challenge/http01"
	"github.com/go-acme/lego/v4/lego"
	"github.com/go-acme/lego/v4/registration"
)

type CertCache interface {
	GetCertificate(key string) ([]byte, []byte, error)
	SetCertificate(key string, cert []byte, privateKey []byte) error
	GetUserJSON(key string) ([]byte, error)
	SetUserJSON(key string, data []byte) error
}

const DefaultRenewalAge = time.Hour * 24 * 30
const DefaultRenewalCheckDuration = time.Hour * 24

type AcmeClient struct {
	email                string
	domains              []string
	ctx                  context.Context
	cacher               CertCache
	cacheKey             string
	keyType              certcrypto.KeyType
	renewalCheckDuration time.Duration
	renewalAge           time.Duration
	access               sync.RWMutex
	caDirURL             string
	logger               *log.Logger
	currentCert          tls.Certificate
	certBytes            []byte
	keyBytes             []byte
	user                 *LegoUser
}

type AcmeClientOption func(*AcmeClient)

// WithLogger sets a custom logger for the AcmeClient.  If not set, it will use the default logger
// from log.Default().
func WithLogger(logger *log.Logger) AcmeClientOption {
	return func(c *AcmeClient) {
		c.logger = logger
	}
}

// WithCache sets a CertCache implementation for the AcmeClient to use for storing certificates.
func WithCache(cacher CertCache) AcmeClientOption {
	return func(c *AcmeClient) {
		c.cacher = cacher
	}
}

// WithCADirURL sets the CA directory URL for the AcmeClient. It is used to specify the base URL of the ACME server.
// If not supplied, the default LetsEncrypt directory endpoint will be used
func WithCADirURL(url string) AcmeClientOption {
	return func(c *AcmeClient) {
		c.caDirURL = url
	}
}

// WithKeyType sets the key type for the AcmeClient. It is used to specify the type of key to generate for the certificate.
// The default is certcrypto.EC256, but you can set it to certcrypto.RSA2048 or other supported key types.
func WithKeyType(keyType certcrypto.KeyType) AcmeClientOption {
	return func(c *AcmeClient) {
		c.keyType = keyType
	}
}

// WithRenewalAge sets the duration of time remaining on a certificate before it is considered for renewal.
// This must not be longer than the term of the certificate, else we would always be trying to renew it.
// If not set, it defaults to 30 days (DefaultRenewalAge) which is fine as most ACME providers issue certificates
// with a 90-day validity period.  Over time, that period will shorten as follows:
//
//	Upcoming Reductions and Timeline (as of April 2025 CA/Browser Forum vote):
//	   Current (until March 14, 2026): Maximum lifetime for TLS certificates is 398 days.
//	   Starting March 15, 2026: Maximum lifetime will be reduced to 200 days.
//	   Starting March 15, 2027: Maximum lifetime will be reduced to 100 days.
//	   Starting March 15, 2029: Maximum lifetime will be reduced to 47 days.
func WithRenewalAge(age time.Duration) AcmeClientOption {
	return func(c *AcmeClient) {
		c.renewalAge = age
		if c.renewalAge <= 0 {
			c.renewalAge = DefaultRenewalAge
		}
	}
}

// WithRenewalCheckDuration sets the duration between checks for certificate renewal.
// This is the interval at which the client will check if the certificate needs to be renewed.
// It defaults to 24 hours (DefaultRenewalCheckDuration) but can be set to a different value.
// The duration must be between 1 hour and 30 days. If a value outside this range is provided, it will be clamped to
func WithRenewalCheckDuration(duration time.Duration) AcmeClientOption {
	return func(c *AcmeClient) {
		c.renewalCheckDuration = duration
		if c.renewalCheckDuration <= 0 {
			c.renewalCheckDuration = DefaultRenewalCheckDuration
		} else {
			c.renewalCheckDuration = min(c.renewalCheckDuration, 30*24*time.Hour)
			c.renewalCheckDuration = max(c.renewalCheckDuration, 1*time.Hour)
		}
	}
}

// NewAcmeClient creates a new ACME client for managing TLS certificates.
// It initializes the client with the provided email, domain names, and options.
// If caching is enabled and a valid certificate is found, it will be used; otherwise, a new certificate will be
// obtained from Let's Encrypt. If the CA directory URL is not provided, it defaults to the production
// Let's Encrypt directory endpoint. If we cannot get a certificate from the cache or Let's Encrypt, an error is returned.
// The client will automatically renew any returned certificate in the background.
// The returned client can be used with tls.Config.GetCertificate to provide the TLS certificate for the specified domains.
func NewAcmeClient(ctx context.Context, email string, domainNames []string, opts ...AcmeClientOption) (*AcmeClient, error) {
	var err error

	c := initClient(ctx, email, domainNames, opts...)

	// If caching is enable, try to load the certificate from the cache.  The cacheKey is calculated based on the domain names
	// so if the domain names change, the cache key will change and a new certificate will be fetched.
	if c.cacher != nil {
		c.certBytes, c.keyBytes, err = c.cacher.GetCertificate(c.cacheKey)
		if err == nil {
			c.logf("Loaded certificate from cache for domains: %v", c.domains)
			// Parse the certificate to check if it's still valid
			if block, _ := pem.Decode(c.certBytes); block != nil {
				certIsGood := false
				if parsedCert, err := x509.ParseCertificate(block.Bytes); err == nil {
					// if we get here, let's assume the cert is good and check other things
					certIsGood = true
					if time.Now().After(parsedCert.NotAfter) {
						certIsGood = false
					}
				}
				if certIsGood {
					// Attempt to load the user from the cache as well, but don't fail if we can't
					if c.user, err = c.GetCachedUser(); err == nil && c.user != nil {
						c.logf("Loaded user %s from cache for domains: %v", c.user.GetUserURI(), c.domains)
					} else if err != nil {
						c.logf("Error %s getting user from cache for domains: %v", err.Error(), c.domains)
					}
					if c.currentCert, err = tls.X509KeyPair(c.certBytes, c.keyBytes); err == nil {
						goto RETURN_CERT
					}
				}
			}
		}
	}
	// Wasn't cached or was invalid, so we need to get a new cert
	c.logf("Invalid or expired cached certificate for domains: %v, obtaining new certificate", c.domains)
	c.currentCert, c.certBytes, c.keyBytes, err = c.getOrCreateLetsEncryptCert()
	if err != nil {
		return nil, err
	}
	if c.cacher != nil {
		if err = c.cacher.SetCertificate(c.cacheKey, c.certBytes, c.keyBytes); err != nil {
			return nil, fmt.Errorf("error caching certificate: %w", err)
		}
	}
RETURN_CERT:
	go c.renewer()
	return c, nil
}

func initClient(ctx context.Context, email string, domainNames []string, opts ...AcmeClientOption) *AcmeClient {
	c := new(AcmeClient)
	c.ctx = ctx
	c.email = email
	c.domains = domainNames
	c.caDirURL = lego.LEDirectoryProduction
	c.logger = log.Default()
	c.keyType = certcrypto.EC256
	c.renewalAge = DefaultRenewalAge
	c.renewalCheckDuration = 24 * time.Hour
	for _, opt := range opts {
		opt(c)
	}
	c.cacheKey = c.calcCacheKey()
	return c
}

// calcCacheKey generates a cache key based on the domain names.  This is used to store and retrieve the certificate
// from the cache. Any changes to the domains slice causes a change in the cache key, so the certificate will be
// re-fetched from the ACME provider.  Key names are hex strings composed of 0...9 and a...f so they are safe for use as filenames.
func (c *AcmeClient) calcCacheKey() string {
	md5sum := md5.Sum([]byte(strings.Join(c.domains, ":")))
	return fmt.Sprintf("%x", md5sum[:])
}

func (c *AcmeClient) logf(format string, args ...interface{}) {
	if c.logger != nil {
		c.logger.Printf(format, args...)
	}
}

func (c *AcmeClient) renewer() {
	var (
		ticker *time.Ticker
	)
	c.logf("checking for ACME renewal every %s", c.renewalCheckDuration.String())
	ticker = time.NewTicker(c.renewalCheckDuration)
	defer ticker.Stop()
	for {
		select {
		case <-c.ctx.Done():
			return
		case <-ticker.C:
			var (
				certBytes, keyBytes []byte
				newCert             tls.Certificate
				err                 error
			)
			// Check if the certificate is about to expire
			if !c.WillExpireWithin(c.renewalAge) {
				continue
			}
			c.logf("Attempting to renew the certificate for domains: %v", c.domains)
			newCert, certBytes, keyBytes, err = c.getOrCreateLetsEncryptCert()
			if err != nil {
				c.logf("Error renewing certificate: %v", err)
				continue
			}
			// Use the new certificate
			c.access.Lock()
			c.currentCert = newCert
			c.certBytes = certBytes
			c.keyBytes = keyBytes
			c.access.Unlock()
			// Cache the new certificate if a cacher is set
			if c.cacher != nil {
				if err = c.cacher.SetCertificate(c.cacheKey, certBytes, keyBytes); err != nil {
					c.logf("Error caching certificate: %v", err)
					continue
				}
			}
		}
	}
}

// WillExpireWithin checks if the current certificate will expire within the specified duration.
// It returns false if the certificate is valid and will not expire within the duration, else it will return true.
// If the certificate is not valid or cannot be parsed, it will also return true, indicating that a renewal is needed.
func (c *AcmeClient) WillExpireWithin(d time.Duration) bool {
	c.access.RLock()
	block, _ := pem.Decode(c.certBytes)
	c.access.RUnlock()
	if block != nil {
		if parsedCert, err := x509.ParseCertificate(block.Bytes); err == nil {
			if time.Until(parsedCert.NotAfter) > d {
				c.logf("Certificate for domains %v will not expire within %s (%s)", c.domains, d.String(), parsedCert.NotAfter.String())
				return false
			} else {
				c.logf("Certificate for domains %v WILL EXPIRE within %s (%s)", c.domains, d.String(), parsedCert.NotAfter.String())
				return true
			}
		} else {
			c.logf("Error parsing certificate: %v", err)
		}
	} else {
		c.logf("No valid certificate found, renewing")
	}
	return true
}

// GetCert retrieves a TLS certificate for the given CertificateRequestInfo.
// It is designed to be used with the tls.Config.GetCertificate function.
func (c *AcmeClient) GetCert(info *tls.ClientHelloInfo) (*tls.Certificate, error) {
	c.access.RLock()
	defer c.access.RUnlock()
	return &c.currentCert, nil
}

// getOrCreateLetsEncryptCert retrieves a Let's Encrypt certificate
// note that the certificate, private key, and the parsed version of those in the form of a tls.Certificate
// are returned as parameters so that the caller can decide to use them or keep using an older version
// in the event an error is encountered.
func (c *AcmeClient) getOrCreateLetsEncryptCert() (tls.Certificate, []byte, []byte, error) {
	var (
		certs   *certificate.Resource
		tlsCert tls.Certificate
		err     error
	)

	// Try to load the user from the cache.  This will return nil if caching is not enabled or the user is not found.
	c.user, err = c.GetCachedUser()
	if err == nil {
		if c.user != nil {
			c.logf("Loaded user from cache for domains: %v", c.domains)
		} else {
			c.logf("User not found in cache for domains: %v", c.domains)
		}
	} else {
		c.logf("Error %s getting user from cache for domains: %v", err.Error(), c.domains)
	}

	if c.user == nil {
		c.logf("Creating new user for domains: %v", c.domains)
		c.user = &LegoUser{Email: c.email}
		c.user.key, err = certcrypto.GeneratePrivateKey(certcrypto.EC256)
		if err != nil {
			return tlsCert, nil, nil, fmt.Errorf("failed to generate private key: %w", err)
		}
	}

	config := lego.NewConfig(c.user)
	config.CADirURL = c.caDirURL
	config.Certificate.KeyType = c.keyType

	client, err := lego.NewClient(config)
	if err != nil {
		return tlsCert, nil, nil, fmt.Errorf("lego client error: %w", err)
	}
	if err = client.Challenge.SetHTTP01Provider(http01.NewProviderServer("", "80")); err != nil {
		return tlsCert, nil, nil, fmt.Errorf("lego http01 provider error: %w", err)
	}

	// If the user is new or doesn't have a registration, register them.
	if c.user.Registration == nil {
		var reg *registration.Resource
		reg, err = client.Registration.Register(registration.RegisterOptions{TermsOfServiceAgreed: true})
		if err != nil {
			return tlsCert, nil, nil, fmt.Errorf("lego registration error: %w", err)
		}
		c.user.Registration = reg
		if err = c.SetCacheUser(c.user); err != nil {
			c.logf("failed to cache user: %v", err)
		}
	}

	request := certificate.ObtainRequest{
		Domains: c.domains,
		Bundle:  true,
	}
	certs, err = client.Certificate.Obtain(request)
	if err != nil {
		return tlsCert, nil, nil, fmt.Errorf("lego obtain cert error: %w", err)
	}
	tlsCert, err = tls.X509KeyPair(certs.Certificate, certs.PrivateKey)
	if err != nil {
		return tlsCert, nil, nil, fmt.Errorf("failed to load cert: %w", err)
	}
	return tlsCert, certs.Certificate, certs.PrivateKey, nil
}
