# CertUtils

The certurils package is a set of utilities for working with X.509 certificates.
Included are functions for:

* Creating self-signed certificates
* Loading a CA pool from disk
* Creating a short-lived certificate from an ACME provider (Let's Encrypt)

## Creating a self-signed certificate
Here is an example of creating a self-signed certificate for a router device with the
SAN is an IP address.

```go
	cn := "myrouter.bluesun.net"
	subject := pkix.Name{
		Country:      []string{"US"},
		Organization: []string{"Blue Sun Corporation"},
		CommonName:   cn,
	}
	ips := make([]net.IP, 0)
	ips = append(ips, net.ParseIP("10.34.56.78"))
	newCert, newKey, err = certCreator.MakeNew(subject, certAge, 2048, nil, ips)
	// Now you can use newCert and newKey to upload to your router
	// they are in PEM format.
	err = uploadFileContents(d, routerConn, "/management.crt", newCert)
	if err != nil {
		return fmt.Errorf("failed to upload certificate: %w", err)
	}
	err = uploadFileContents(d, routerConn, "/management.key", newKey)
	if err != nil {
        return fmt.Errorf("failed to upload key: %w", err)
	}
```

## Using an ACME provided certificate for a web server
Here is an example of using an ACME provider to create a short-lived certificate for a web server.
While a new certificate could be created every time the server starts, it is more efficient to
cache the certificate in some non-volitile storage and reuse it.  Especially since most ACME
providers (like Let's Encrypt) have rate limits on how many certificates can be issued per domain.
The certutils package provides a disk cache or Redis cache for this purpose.

```go
    email := "jdoe@bluesun.com"
	externalHostNames := []string{"myserver.bluesun.net", "myserver2.bluesun.net"}
    cacher := &diskcache.DiskCertCache{Dir: "/var/myserver/certcache"}
    certClient, err = certutils.NewAcmeClient(ctx, email, externalHostNames,
        certutils.WithLogger(log.Default()),
        certutils.WithCache(cacher))
    if err != nil {
        log.Fatalf("unable to load from cache or acquire a certificate from ACME provider: %s", err)
    }
	srv := &http.Server{
		Addr:              ":443"
		ReadHeaderTimeout: 5 * time.Second,
		Handler:           createMainRouter(),
		TLSConfig: &tls.Config{
            MinVersion: tls.VersionTLS12,
			GetCertificate = certClient.GetCert,
        },
	}
    if err = srv.ListenAndServeTLS("", ""); err != nil {
        log.Fatal(err)
    }
```

Notice that the ListenAndServeTLS function is called with empty strings for the certificate and key.
This is because the TLS configuration is set to use the GetCertificate function from the certutils package.
This function will be called by the server to get the certificate for each request, allowing for 
short-lived certificates to be used without needing to restart the server.  In the event that the certificate is 
not found in the cache, expired, or doesn't match the SAN name list used in NewAcmeClient(), the 
certutils package will automatically request a new certificate from the ACME provider.

The NewAcmeClient() function must be called with a context, and that context should be tied to the lifetime 
of the server.  The context is used to cancel the background Go routine used to refresh the certificate.

The package currently uses the HTTP-01 challenge type to prove ownership of the domain.  The certClient returned by 
NewAcmeClient() will automatically start a listening HTTP server on port 80 to respond to the challenge requests 
when it needs.  The hosting process must ensure that port 80 is available for this to work.  The HTTP server will
be shutdown after completion of the challenge, reducing any attack surface.
If the process is not able to listen on port 80, the certClient will return an error when trying to get a 
certificate.  The certutils package does not currently support any other challenge types, but it could be 
added in the future if needed.

### Disk Caching of Certificates
The disk cache is a simple implementation that stores the certificate and key in PEM format as well as the ACME User
in JSON format within a directory on disk. The file names are a "cache key" calculated from the SAN names used 
in NewAcmeClient().  The directory will be created if it does not exist, though the process must have permissions
to create files in the directory.
Old certificates are not automatically deleted, so the cache directory may grow over time.

```go
	cacher := &diskcache.DiskCertCache{
        Dir: "/var/myserver/certcache",
    }
```

### Redis Caching of Certificates
The Redis cache is a more advanced implementation that stores the certificate and key in PEM format as well as the ACME
User in JSON format within in a Redis database. The key is an optional prefix plus a "cache key" calculated from 
the SAN names used in NewAcmeClient().
Old certificates can be automatically deleted after a configurable time period by setting the CacheTimeout value
in the RedisCertCache struct:

```go
    cacher := &redis.RedisCertCache{
        Pool: redisPool,
        CacheTimeout: 100 * 24 * time.Hour, // delete old certificates after 100 days
	      KeyPrefix: "myserver-cert::", // optional prefix for the keys in Redis
    }
```

### Multiple Servers Using the Same Certificate
The certutils package is not designed to allow multiple servers to use the same ACME provided certificate as there is no
synchronization between the servers.  If multiple servers are using the same certificate, they will all
try to refresh the certificate at the same time, which can lead to rate limiting issues with the ACME provider.
If your service needs multiple servers in a pool to handle requests, it is recommended to use a load balancer
which will handle the TLS termination and certificate management.