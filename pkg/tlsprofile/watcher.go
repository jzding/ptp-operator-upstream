package tlsprofile

import (
	"context"
	"reflect"

	configv1 "github.com/openshift/api/config/v1"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

// TLSProfileWatcher watches the APIServer CR and invokes a callback when the TLS profile changes.
type TLSProfileWatcher struct {
	Client                client.Client
	InitialTLSProfileSpec *configv1.TLSProfileSpec
	OnProfileChange       func(ctx context.Context, old, new *configv1.TLSProfileSpec)
}

// Reconcile handles changes to the APIServer CR.
func (w *TLSProfileWatcher) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	// Only react to the "cluster" APIServer
	if req.Name != "cluster" {
		return ctrl.Result{}, nil
	}

	apiServer := &configv1.APIServer{}
	if err := w.Client.Get(ctx, req.NamespacedName, apiServer); err != nil {
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}

	newProfileSpec := ResolveTLSProfileSpec(apiServer.Spec.TLSSecurityProfile)

	// Check if profile changed
	if !reflect.DeepEqual(w.InitialTLSProfileSpec, newProfileSpec) {
		if w.OnProfileChange != nil {
			w.OnProfileChange(ctx, w.InitialTLSProfileSpec, newProfileSpec)
		}
		// Update the initial profile spec for future comparisons
		w.InitialTLSProfileSpec = newProfileSpec
	}

	return ctrl.Result{}, nil
}

// SetupWithManager sets up the controller with the Manager.
func (w *TLSProfileWatcher) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&configv1.APIServer{}).
		WithEventFilter(TLSProfileChangedPredicate()).
		Complete(w)
}
