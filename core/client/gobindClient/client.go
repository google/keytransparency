// TODO(amarcedone) : rename package to gobind_client after https://github.com/golang/go/issues/17359 is solved.
package gobindClient

import (
	"context"
	"fmt"
	"github.com/google/keytransparency/cmd/keytransparency-client/grpcc"
	"github.com/google/trillian"
	"github.com/google/trillian/client"
	"github.com/google/trillian/crypto/keys/pem"
	"github.com/google/trillian/merkle/hashers"
	_ "github.com/google/trillian/merkle/objhasher" // Used to init the package so that the hasher gets registered (needed by the bGetVerifierFromParams function)
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"net"
	"time"

	tpb "github.com/google/keytransparency/core/proto/keytransparency_v1_types"

	"crypto/tls"
	"crypto/x509"
	"github.com/gogo/protobuf/proto"
	"github.com/google/keytransparency/core/client/kt"
	"github.com/google/keytransparency/core/crypto/keymaster"
	"github.com/google/keytransparency/core/crypto/vrf/p256"
	pb "github.com/google/keytransparency/impl/proto/keytransparency_v1_service"
	"log"
)

type BClientParams struct {
	KtURL        string
	MapID        int64
	KtTLSCertPEM []byte
	VrfPubPEM    []byte
	KtSigPubKey  []byte
	LogPEM       []byte
}

// TODO(amarcedone) consider persisting the client or at least the trusted smr, to gain efficiency and stronger consistency guarantees.

func NewBClientParams(KtURL string, MapID int64, KtTLSCertPEM, VrfPubPEM, KtSigPubKey, LogPEM []byte) *BClientParams {
	// Note: byte arrays need to be explicitly cloned due to some gobind limitations.
	cKtTLSCertPEM := make([]byte, len(KtTLSCertPEM))
	copy(cKtTLSCertPEM, KtTLSCertPEM)
	cVrfPubPEM := make([]byte, len(VrfPubPEM))
	copy(cVrfPubPEM, VrfPubPEM)
	cKtSigPubKey := make([]byte, len(KtSigPubKey))
	copy(cKtSigPubKey, KtSigPubKey)
	cLogPEM := make([]byte, len(LogPEM))
	copy(cLogPEM, LogPEM)

	return &BClientParams{KtURL, MapID, cKtTLSCertPEM, cVrfPubPEM, cKtSigPubKey, cLogPEM}
}

func BGetEntry(timeoutInMilliseconds int, clientParams *BClientParams, userID, appID string) ([]byte, error) {

	timeout := time.Duration(timeoutInMilliseconds) * time.Millisecond
	c, err := GetClient(*clientParams, "")
	if err != nil {
		return nil, fmt.Errorf("GetEntry failed: error connecting: %v", err)
	}
	ctx, _ := context.WithTimeout(context.Background(), timeout)
	entry, smr, err := c.GetEntry(ctx, userID, appID)
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

func GetClient(clientParams BClientParams, clientSecretFile string) (*grpcc.Client, error) {
	// TODO(amarcedone) For now clientSecretFile is not needed as there is no authentication. Consider removing.

	cc, err := dial(clientParams.KtURL, clientParams.KtTLSCertPEM, clientSecretFile)
	if err != nil {
		return nil, fmt.Errorf("Error Dialing %v: %v", clientParams.KtURL, err)
	}

	// Log verifier.
	logPubKey, err := pem.UnmarshalPublicKey(string(clientParams.LogPEM))
	if err != nil {
		return nil, fmt.Errorf("Failed to open public key %v: %v", string(clientParams.LogPEM), err)
	}

	hasher, err := hashers.NewLogHasher(trillian.HashStrategy_OBJECT_RFC6962_SHA256)
	if err != nil {
		return nil, fmt.Errorf("Failed retrieving LogHasher from registry: %v", err)
	}
	log := client.NewLogVerifier(hasher, logPubKey)

	verifier, err := keymaster.NewVerifierFromPEM(clientParams.KtSigPubKey)
	if err != nil {
		return nil, fmt.Errorf("Error creating verifier from PEM encoded key: %v", err)
	}

	vrfVerifier, err := p256.NewVRFVerifierFromPEM(clientParams.VrfPubPEM)
	if err != nil {
		return nil, fmt.Errorf("Error parsing vrf public key: %v", err)
	}

	cli := pb.NewKeyTransparencyServiceClient(cc)
	return grpcc.New(cli, vrfVerifier, verifier, log), nil
}

func dial(ktURL string, caPEM []byte, clientSecretFile string) (*grpc.ClientConn, error) {
	// TODO(amarcedone) For now clientSecretFile is not needed as there is no authentication. Consider removing.

	var opts []grpc.DialOption
	// TODO(amarcedone) Copied from root.go. Figure out why we have "if true" here. Perhaps for scope?
	if true {
		host, _, err := net.SplitHostPort(ktURL)
		if err != nil {
			return nil, err
		}
		var creds credentials.TransportCredentials
		if len(caPEM) != 0 {
			var err error
			cp := x509.NewCertPool()
			if !cp.AppendCertsFromPEM(caPEM) {
				return nil, fmt.Errorf("credentials: failed to append certificates")
			}
			creds, err = credentials.NewTLS(&tls.Config{ServerName: host, RootCAs: cp}), nil
			if err != nil {
				return nil, err
			}
		} else {
			// Use the local set of root certs.
			creds = credentials.NewClientTLSFromCert(nil, host)
		}
		opts = append(opts, grpc.WithTransportCredentials(creds))
	}

	// AUTHENTICATION is not needed for gobind clients as they only perform get requests.
	//// Add authentication information for the grpc. Only one type of credential
	//// should exist in an RPC call. Fake credentials have the highest priority, followed
	//// by Client credentials and Service Credentials.
	//fakeUserID := viper.GetString("fake-auth-userid")
	//switch {
	//case fakeUserID != "":
	//	opts = append(opts, grpc.WithPerRPCCredentials(
	//		authentication.GetFakeCredential(fakeUserID)))
	//case clientSecretFile != "":
	//	creds, err := getCreds(clientSecretFile)
	//	if err != nil {
	//		return nil, err
	//	}
	//	opts = append(opts, grpc.WithPerRPCCredentials(creds))
	//case serviceKeyFile != "":
	//	creds, err := getServiceCreds(serviceKeyFile)
	//	if err != nil {
	//		return nil, err
	//	}
	//	opts = append(opts, grpc.WithPerRPCCredentials(creds))
	//}

	cc, err := grpc.Dial(ktURL, opts...)
	if err != nil {
		return nil, err
	}
	return cc, nil
}

func BSetCustomLogger(writer BWriter) {
	kt.Vlog = log.New(writer, "", log.Lshortfile)
}

// Local copy of io.Writer interface used to redirect logs.
type BWriter interface {
	Write(p []byte) (n int, err error)
}