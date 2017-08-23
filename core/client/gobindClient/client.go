// TODO(amarcedone) : rename package to gobind_client after https://github.com/golang/go/issues/17359 is solved.
package gobindClient

import (
	"context"
	"fmt"
	"github.com/google/keytransparency/cmd/keytransparency-client/grpcc"
	_ "github.com/google/trillian/merkle/coniks"    // Register coniks
	_ "github.com/google/trillian/merkle/objhasher" // Used to init the package so that the hasher gets registered

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"net"
	"time"

	"crypto/tls"
	"crypto/x509"
	"github.com/google/keytransparency/core/client/kt"
	tpb "github.com/google/keytransparency/core/proto/keytransparency_v1_types"
	spb "github.com/google/keytransparency/impl/proto/keytransparency_v1_service"

	"bytes"
	"github.com/benlaurie/objecthash/go/objecthash"
	"io/ioutil"
	"log"
)

var (
	initialized bool

	clients map[string]*grpcc.Client = make(map[string]*grpcc.Client)

	timeout time.Duration

	// Vlog is the verbose logger. By default it outputs to /dev/null.
	Vlog = log.New(ioutil.Discard, "", 0)
)

func checkInitialized() error {
	if initialized == false {
		return fmt.Errorf("The keytransparency gobindClient has not been intialized yet. Please call init first.")
	}
	return nil
}

func BInit(timeoutInMs int32) error {
	if initialized {
		fmt.Errorf("The library was already initialized.")
	}

	initialized = true

	timeout = time.Duration(timeoutInMs) * time.Millisecond

	// TODO Persistence_path processing will go here.

	return nil
}

func BAddKtServer(ktURL string, insecureTLS bool, ktTLSCertPEM []byte, domainInfoHash []byte) error {
	if _, exists := clients[ktURL]; exists == true {
		fmt.Errorf("The KtServer connection for %v already exists", ktURL)
	}

	// TODO Add URL validation here.

	cc, err := dial(ktURL, insecureTLS, ktTLSCertPEM)
	if err != nil {
		return fmt.Errorf("Error Dialing %v: %v", ktURL, err)
	}

	ktClient := spb.NewKeyTransparencyServiceClient(cc)

	ctx, _ := context.WithTimeout(context.Background(), timeout)
	config, err := ktClient.GetDomainInfo(ctx, &tpb.GetDomainInfoRequest{})
	if err != nil {
		return fmt.Errorf("Error getting config: %v", err)
	}

	if len(domainInfoHash) == 0 {
		Vlog.Print("Warning: no domainInfoHash provided. Key material from the server will be trusted.")
	} else {
		if got := objecthash.ObjectHash(config); bytes.Compare(got[:], domainInfoHash) != 0 {
			return fmt.Errorf("The KtServer %v returned a domainInfoResponse inconsistent with the provided domainInfoHash")
		}
	}

	client, err := grpcc.NewFromConfig(cc, config)
	if err != nil {
		return fmt.Errorf("Error adding the KtServer: %v", err)
	}

	clients[ktURL] = client
	return nil
}

func BGetEntry(ktURL, userID, appID string) ([]byte, error) {

	if err := checkInitialized(); err != nil {
		return []byte{}, err
	}

	client, exists := clients[ktURL]
	if !exists {
		fmt.Errorf("A connection to %v does not exists. Please call BAddKtServer first", ktURL)
	}

	ctx, _ := context.WithTimeout(context.Background(), timeout)
	entry, smr, err := client.GetEntry(ctx, userID, appID)
	if err != nil {
		return nil, fmt.Errorf("GetEntry failed: %v", err)
	}
	// TODO(amarcedone): Consider returning or persisting smr it to verify consistency over time
	_ = smr
	//encodedSmr, err := proto.Marshal(smr)
	//if err != nil {
	//	return nil, fmt.Errorf("GetEntry failed: error serializing smr: %v", err)
	//}

	return entry, nil
}

func dial(ktURL string, insecureTLS bool, ktTLSCertPEM []byte) (*grpc.ClientConn, error) {

	creds, err := transportCreds(ktURL, insecureTLS, ktTLSCertPEM)

	cc, err := grpc.Dial(ktURL, grpc.WithTransportCredentials(creds))
	if err != nil {
		return nil, err
	}
	return cc, nil
}

func transportCreds(ktURL string, insecure bool, ktTLSCertPEM []byte) (credentials.TransportCredentials, error) {

	host, _, err := net.SplitHostPort(ktURL)
	if err != nil {
		return nil, err
	}

	switch {
	case insecure: // Impatient insecure.
		Vlog.Printf("Warning: Skipping verification of KT Server's TLS certificate.")
		return credentials.NewTLS(&tls.Config{
			InsecureSkipVerify: true,
		}), nil

	case len(ktTLSCertPEM) != 0: // Custom CA Cert.
		cp := x509.NewCertPool()
		if !cp.AppendCertsFromPEM(ktTLSCertPEM) {
			return nil, fmt.Errorf("credentials: failed to append certificates")
		}
		creds := credentials.NewTLS(&tls.Config{ServerName: host, RootCAs: cp})
		return creds, nil

	default: // Use the local set of root certs.
		return credentials.NewClientTLSFromCert(nil, host), nil
	}
}

func BSetCustomLogger(writer BWriter) {
	kt.Vlog = log.New(writer, "", log.Lshortfile)
	Vlog = log.New(writer, "", log.Lshortfile)
}

// Local copy of io.Writer interface used to redirect logs.
type BWriter interface {
	Write(p []byte) (n int, err error)
}
