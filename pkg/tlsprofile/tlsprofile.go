package tlsprofile

import (
	"context"
	"crypto/tls"
	"reflect"

	configv1 "github.com/openshift/api/config/v1"
	"github.com/openshift/library-go/pkg/crypto"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/event"
	"sigs.k8s.io/controller-runtime/pkg/predicate"
)

// FetchAPIServerTLSProfile fetches the TLS security profile from the APIServer CR.
// Returns the default Intermediate profile if not configured.
func FetchAPIServerTLSProfile(ctx context.Context, c client.Client) (*configv1.TLSProfileSpec, error) {
	apiServer := &configv1.APIServer{}
	if err := c.Get(ctx, types.NamespacedName{Name: "cluster"}, apiServer); err != nil {
		return nil, err
	}

	return ResolveTLSProfileSpec(apiServer.Spec.TLSSecurityProfile), nil
}

// ResolveTLSProfileSpec returns the TLSProfileSpec for a given TLSSecurityProfile,
// handling nil, Custom, and well-known profile types.
func ResolveTLSProfileSpec(profile *configv1.TLSSecurityProfile) *configv1.TLSProfileSpec {
	if profile == nil {
		return GetTLSProfileSpec(configv1.TLSProfileIntermediateType)
	}
	if profile.Type == configv1.TLSProfileCustomType && profile.Custom != nil {
		return &profile.Custom.TLSProfileSpec
	}
	return GetTLSProfileSpec(profile.Type)
}

// GetTLSProfileSpec returns the TLSProfileSpec for a given profile type.
func GetTLSProfileSpec(profileType configv1.TLSProfileType) *configv1.TLSProfileSpec {
	var profile *configv1.TLSProfileSpec

	switch profileType {
	case configv1.TLSProfileOldType:
		profile = configv1.TLSProfiles[configv1.TLSProfileOldType]
	case configv1.TLSProfileIntermediateType:
		profile = configv1.TLSProfiles[configv1.TLSProfileIntermediateType]
	case configv1.TLSProfileModernType:
		profile = configv1.TLSProfiles[configv1.TLSProfileModernType]
	default:
		// Default to Intermediate if unknown
		profile = configv1.TLSProfiles[configv1.TLSProfileIntermediateType]
	}

	return profile
}

// NewTLSConfigFromProfile creates a function that configures a tls.Config based on the TLS profile.
// Returns the configuration function and a list of unsupported ciphers.
func NewTLSConfigFromProfile(profileSpec *configv1.TLSProfileSpec) (func(*tls.Config), []string) {
	var unsupportedCiphers []string
	var tlsVersion uint16

	// Convert TLS version string to constant
	if profileSpec.MinTLSVersion != "" {
		ver, err := crypto.TLSVersion(string(profileSpec.MinTLSVersion))
		if err == nil {
			tlsVersion = ver
		} else {
			// Default to TLS 1.2 if parsing fails
			tlsVersion = tls.VersionTLS12
		}
	} else {
		tlsVersion = tls.VersionTLS12
	}

	// Convert cipher suite names to TLS constants
	var cipherSuites []uint16
	if len(profileSpec.Ciphers) > 0 {
		// Convert OpenSSL cipher names to IANA names
		ianaCiphers := crypto.OpenSSLToIANACipherSuites(profileSpec.Ciphers)
		for _, cipher := range ianaCiphers {
			supported := false
			for _, suite := range tls.CipherSuites() {
				if suite.Name == cipher {
					cipherSuites = append(cipherSuites, suite.ID)
					supported = true
					break
				}
			}
			if !supported {
				// Check insecure cipher suites as well
				for _, suite := range tls.InsecureCipherSuites() {
					if suite.Name == cipher {
						cipherSuites = append(cipherSuites, suite.ID)
						supported = true
						break
					}
				}
			}
			if !supported {
				unsupportedCiphers = append(unsupportedCiphers, cipher)
			}
		}
	}

	tlsOpts := func(config *tls.Config) {
		config.MinVersion = tlsVersion
		if len(cipherSuites) > 0 {
			config.CipherSuites = cipherSuites
		}
	}

	return tlsOpts, unsupportedCiphers
}

// TLSProfileChangedPredicate returns a predicate that filters events to only TLS profile changes.
func TLSProfileChangedPredicate() predicate.Predicate {
	return predicate.Funcs{
		CreateFunc: func(e event.CreateEvent) bool {
			return e.Object.GetName() == "cluster"
		},
		UpdateFunc: func(e event.UpdateEvent) bool {
			if e.ObjectNew.GetName() != "cluster" {
				return false
			}
			oldAPI, ok := e.ObjectOld.(*configv1.APIServer)
			if !ok {
				return false
			}
			newAPI, ok := e.ObjectNew.(*configv1.APIServer)
			if !ok {
				return false
			}
			// Only reconcile if TLS profile actually changed
			return !reflect.DeepEqual(
				oldAPI.Spec.TLSSecurityProfile,
				newAPI.Spec.TLSSecurityProfile,
			)
		},
		DeleteFunc: func(e event.DeleteEvent) bool {
			return false
		},
		GenericFunc: func(e event.GenericEvent) bool {
			return false
		},
	}
}
