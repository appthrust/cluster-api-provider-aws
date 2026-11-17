package eks

import (
	"context"
	"encoding/base64"
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	signerv4 "github.com/aws/aws-sdk-go-v2/aws/signer/v4"
	ekstypes "github.com/aws/aws-sdk-go-v2/service/eks/types"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	smithyhttp "github.com/aws/smithy-go/transport/http"
	"github.com/golang/mock/gomock"
	. "github.com/onsi/gomega"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	infrav1 "sigs.k8s.io/cluster-api-provider-aws/v2/api/v1beta2"
	ekscontrolplanev1 "sigs.k8s.io/cluster-api-provider-aws/v2/controlplane/eks/api/v1beta2"
	"sigs.k8s.io/cluster-api-provider-aws/v2/pkg/cloud/scope"
	stsservice "sigs.k8s.io/cluster-api-provider-aws/v2/pkg/cloud/services/sts"
	"sigs.k8s.io/cluster-api-provider-aws/v2/pkg/cloud/services/sts/mock_stsiface"
	clusterv1 "sigs.k8s.io/cluster-api/api/core/v1beta2"
	"sigs.k8s.io/cluster-api/util/secret"
)

func Test_createCAPIKubeconfigSecret(t *testing.T) {
	testCases := []struct {
		name        string
		input       *ekstypes.Cluster
		serviceFunc func() *Service
		wantErr     bool
	}{
		{
			name: "create kubeconfig secret",
			input: &ekstypes.Cluster{
				Name:                 aws.String("cluster-foo"),
				CertificateAuthority: &ekstypes.Certificate{Data: aws.String("LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0t")},
				Endpoint:             aws.String("https://cluster-foo.us-east-2.eks.amazonaws.com"),
			},
			serviceFunc: func() *Service {
				mockCtrl := gomock.NewController(t)
				stsMock := mock_stsiface.NewMockSTSClient(mockCtrl)
				stsMock.EXPECT().PresignGetCallerIdentity(gomock.Any(), gomock.Any(), gomock.Any()).Return(&signerv4.PresignedHTTPRequest{URL: "https://example.com"}, nil)
				stsMock.EXPECT().GetCallerIdentity(gomock.Any(), gomock.Any()).Return(&sts.GetCallerIdentityOutput{
					UserId:  aws.String("FAKEUSERID"),
					Account: aws.String("FAKEACCOUNT"),
					Arn:     aws.String("arn:aws:sts::FAKEACCOUNT:user/FAKEUSERID"),
				}, nil).AnyTimes()

				scheme := runtime.NewScheme()
				_ = infrav1.AddToScheme(scheme)
				_ = ekscontrolplanev1.AddToScheme(scheme)
				_ = corev1.AddToScheme(scheme)

				client := fake.NewClientBuilder().WithScheme(scheme).Build()
				managedScope, _ := scope.NewManagedControlPlaneScope(scope.ManagedControlPlaneScopeParams{
					Client: client,
					Cluster: &clusterv1.Cluster{
						ObjectMeta: metav1.ObjectMeta{
							Namespace: "ns",
							Name:      "capi-cluster-foo",
						},
					},
					ControlPlane: &ekscontrolplanev1.AWSManagedControlPlane{
						ObjectMeta: metav1.ObjectMeta{
							Namespace: "ns",
							Name:      "capi-cluster-foo",
							UID:       types.UID("1"),
						},
						Spec: ekscontrolplanev1.AWSManagedControlPlaneSpec{
							EKSClusterName: "cluster-foo",
						},
					},
				})

				service := NewService(managedScope)
				service.STSClient = stsMock
				return service
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			g := NewWithT(t)

			service := tc.serviceFunc()
			clusterRef := types.NamespacedName{
				Namespace: service.scope.Namespace(),
				Name:      service.scope.Name(),
			}
			err := service.createCAPIKubeconfigSecret(context.TODO(), tc.input, &clusterRef)
			if tc.wantErr {
				g.Expect(err).ToNot(BeNil())
			} else {
				g.Expect(err).To(BeNil())
				var kubeconfigSecret corev1.Secret
				g.Expect(service.scope.Client.Get(context.TODO(), types.NamespacedName{Namespace: "ns", Name: "capi-cluster-foo-kubeconfig"}, &kubeconfigSecret)).To(BeNil())
				g.Expect(kubeconfigSecret.Data).ToNot(BeNil())
				g.Expect(len(kubeconfigSecret.Data)).To(BeIdenticalTo(3))
				g.Expect(kubeconfigSecret.Data[secret.KubeconfigDataName]).ToNot(BeEmpty())
				g.Expect(kubeconfigSecret.Data[relativeKubeconfigKey]).ToNot(BeEmpty())
				g.Expect(kubeconfigSecret.Data[relativeTokenFileKey]).ToNot(BeEmpty())
			}
		})
	}
}

func Test_updateCAPIKubeconfigSecret(t *testing.T) {
	type testCase struct {
		name        string
		input       *ekstypes.Cluster
		secret      *corev1.Secret
		serviceFunc func(tc testCase) *Service
		wantErr     bool
	}
	testCases := []testCase{
		{
			name: "update kubeconfig secret",
			input: &ekstypes.Cluster{
				Name:                 aws.String("cluster-foo"),
				CertificateAuthority: &ekstypes.Certificate{Data: aws.String("")},
				Endpoint:             aws.String("https://F00BA4.gr4.us-east-2.eks.amazonaws.com"),
			},
			secret: &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{
					Namespace: "ns",
					Name:      "capi-cluster-foo-kubeconfig",
					OwnerReferences: []metav1.OwnerReference{
						{
							APIVersion: "controlplane.cluster.x-k8s.io/v1beta2",
							Kind:       "AWSManagedControlPlane",
							Name:       "capi-cluster-foo",
							UID:        "1",
							Controller: aws.Bool(true),
						},
					},
				},
				Data: make(map[string][]byte),
			},
			serviceFunc: func(tc testCase) *Service {
				mockCtrl := gomock.NewController(t)
				stsMock := mock_stsiface.NewMockSTSClient(mockCtrl)
				stsMock.EXPECT().PresignGetCallerIdentity(gomock.Any(), gomock.Any(), gomock.Any()).Return(&signerv4.PresignedHTTPRequest{URL: "https://example.com"}, nil)
				stsMock.EXPECT().GetCallerIdentity(gomock.Any(), gomock.Any()).Return(&sts.GetCallerIdentityOutput{
					UserId:  aws.String("FAKEUSERID"),
					Account: aws.String("FAKEACCOUNT"),
					Arn:     aws.String("arn:aws:sts::FAKEACCOUNT:user/FAKEUSERID"),
				}, nil).AnyTimes()

				scheme := runtime.NewScheme()
				_ = infrav1.AddToScheme(scheme)
				_ = ekscontrolplanev1.AddToScheme(scheme)
				_ = corev1.AddToScheme(scheme)

				client := fake.NewClientBuilder().WithScheme(scheme).WithObjects(tc.secret).Build()
				managedScope, _ := scope.NewManagedControlPlaneScope(scope.ManagedControlPlaneScopeParams{
					Client: client,
					Cluster: &clusterv1.Cluster{
						ObjectMeta: metav1.ObjectMeta{
							Namespace: "ns",
							Name:      "capi-cluster-foo",
						},
					},
					ControlPlane: &ekscontrolplanev1.AWSManagedControlPlane{
						ObjectMeta: metav1.ObjectMeta{
							Namespace: "ns",
							Name:      "capi-cluster-foo",
							UID:       "1",
						},
						Spec: ekscontrolplanev1.AWSManagedControlPlaneSpec{
							EKSClusterName: "cluster-foo",
						},
					},
				})

				service := NewService(managedScope)
				service.STSClient = stsMock
				return service
			},
		},
		{
			name: "detect incorrect ownership on the kubeconfig secret",
			input: &ekstypes.Cluster{
				Name:                 aws.String("cluster-foo"),
				CertificateAuthority: &ekstypes.Certificate{Data: aws.String("")},
				Endpoint:             aws.String("https://F00BA4.gr4.us-east-2.eks.amazonaws.com"),
			},
			secret: &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{
					Namespace: "ns",
					Name:      "capi-cluster-foo-kubeconfig",
				},
				Data: make(map[string][]byte),
			},
			serviceFunc: func(tc testCase) *Service {
				scheme := runtime.NewScheme()
				_ = infrav1.AddToScheme(scheme)
				_ = ekscontrolplanev1.AddToScheme(scheme)
				_ = corev1.AddToScheme(scheme)

				client := fake.NewClientBuilder().WithScheme(scheme).WithObjects(tc.secret).Build()
				managedScope, _ := scope.NewManagedControlPlaneScope(scope.ManagedControlPlaneScopeParams{
					Client: client,
					Cluster: &clusterv1.Cluster{
						ObjectMeta: metav1.ObjectMeta{
							Namespace: "ns",
							Name:      "capi-cluster-foo",
						},
					},
					ControlPlane: &ekscontrolplanev1.AWSManagedControlPlane{
						ObjectMeta: metav1.ObjectMeta{
							Namespace: "ns",
							Name:      "capi-cluster-foo",
							UID:       "1",
						},
						Spec: ekscontrolplanev1.AWSManagedControlPlaneSpec{
							EKSClusterName: "cluster-foo",
						},
					},
				})

				service := NewService(managedScope)
				return service
			},
			wantErr: true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			g := NewWithT(t)

			service := tc.serviceFunc(tc)
			err := service.updateCAPIKubeconfigSecret(context.TODO(), tc.secret, tc.input)
			if tc.wantErr {
				g.Expect(err).ToNot(BeNil())
			} else {
				g.Expect(err).To(BeNil())
				var kubeconfigSecret corev1.Secret
				g.Expect(service.scope.Client.Get(context.TODO(), types.NamespacedName{Namespace: "ns", Name: "capi-cluster-foo-kubeconfig"}, &kubeconfigSecret)).To(BeNil())
				g.Expect(kubeconfigSecret.Data).ToNot(BeNil())
				g.Expect(len(kubeconfigSecret.Data)).To(BeIdenticalTo(3))
				g.Expect(kubeconfigSecret.Data[secret.KubeconfigDataName]).ToNot(BeEmpty())
				g.Expect(kubeconfigSecret.Data[relativeKubeconfigKey]).ToNot(BeEmpty())
				g.Expect(kubeconfigSecret.Data[relativeTokenFileKey]).ToNot(BeEmpty())
			}
		})
	}
}

// sequenceCredentials returns its credentials in order, one per Retrieve.
type sequenceCredentials struct {
	creds []aws.Credentials
	calls int
}

func (p *sequenceCredentials) Retrieve(context.Context) (aws.Credentials, error) {
	creds := p.creds[min(p.calls, len(p.creds)-1)]
	p.calls++
	return creds, nil
}

func Test_generateTokenSigningCredentialLifetime(t *testing.T) {
	temporary := func(accessKeyID string, lifetime time.Duration) aws.Credentials {
		return aws.Credentials{
			AccessKeyID:     accessKeyID,
			SecretAccessKey: "secret",
			SessionToken:    "session",
			CanExpire:       true,
			Expires:         time.Now().Add(lifetime),
		}
	}
	testCases := []struct {
		name          string
		creds         []aws.Credentials
		wantAccessKey string
		wantRetrieves int
	}{
		{
			// Outside the SDK's five-minute container-credential refresh
			// window, but expiring before the token would be replaced.
			name:          "credentials expiring within the token lifetime are refreshed",
			creds:         []aws.Credentials{temporary("EXPIRING", 8*time.Minute), temporary("FRESH", 6*time.Hour)},
			wantAccessKey: "FRESH",
			wantRetrieves: 2,
		},
		{
			name:          "credentials outliving the token are reused",
			creds:         []aws.Credentials{temporary("CURRENT", 3*time.Hour), temporary("UNUSED", 6*time.Hour)},
			wantAccessKey: "CURRENT",
			wantRetrieves: 1,
		},
		{
			name:          "non-expiring credentials are reused",
			creds:         []aws.Credentials{{AccessKeyID: "STATIC", SecretAccessKey: "secret"}, temporary("UNUSED", 6*time.Hour)},
			wantAccessKey: "STATIC",
			wantRetrieves: 1,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			g := NewWithT(t)

			provider := &sequenceCredentials{creds: tc.creds}
			// The same cache options the SDK applies to EKS Pod Identity and ECS credentials.
			cache := aws.NewCredentialsCache(provider, func(o *aws.CredentialsCacheOptions) { o.ExpiryWindow = 5 * time.Minute })
			// Warm the cache as earlier reconciles would have.
			_, err := cache.Retrieve(context.TODO())
			g.Expect(err).To(BeNil())

			stsClient := sts.New(sts.Options{
				Region:      "us-east-1",
				Credentials: cache,
				HTTPClient: smithyhttp.ClientDoFunc(func(r *http.Request) (*http.Response, error) {
					body := `<GetCallerIdentityResponse><GetCallerIdentityResult><Arn>arn:aws:sts::123456789012:assumed-role/capa/session</Arn><UserId>USERID</UserId><Account>123456789012</Account></GetCallerIdentityResult></GetCallerIdentityResponse>`
					return &http.Response{StatusCode: http.StatusOK, Header: http.Header{"Content-Type": []string{"text/xml"}}, Body: io.NopCloser(strings.NewReader(body)), Request: r}, nil
				}),
			})
			scheme := runtime.NewScheme()
			g.Expect(infrav1.AddToScheme(scheme)).To(Succeed())
			g.Expect(ekscontrolplanev1.AddToScheme(scheme)).To(Succeed())
			managedScope, err := scope.NewManagedControlPlaneScope(scope.ManagedControlPlaneScopeParams{
				Client:  fake.NewClientBuilder().WithScheme(scheme).Build(),
				Cluster: &clusterv1.Cluster{ObjectMeta: metav1.ObjectMeta{Namespace: "ns", Name: "capi-cluster-foo"}},
				ControlPlane: &ekscontrolplanev1.AWSManagedControlPlane{
					ObjectMeta: metav1.ObjectMeta{Namespace: "ns", Name: "capi-cluster-foo"},
					Spec:       ekscontrolplanev1.AWSManagedControlPlaneSpec{EKSClusterName: "cluster-foo"},
				},
			})
			g.Expect(err).To(BeNil())
			service := NewService(managedScope)
			service.STSClient = stsservice.NewClientWrapper(stsClient)

			token, err := service.generateToken()
			g.Expect(err).To(BeNil())

			g.Expect(token).To(HavePrefix(tokenPrefix))
			rawURL, err := base64.RawURLEncoding.DecodeString(strings.TrimPrefix(token, tokenPrefix))
			g.Expect(err).To(BeNil())
			presigned, err := url.Parse(string(rawURL))
			g.Expect(err).To(BeNil())
			g.Expect(presigned.Query().Get("X-Amz-Credential")).To(HavePrefix(tc.wantAccessKey + "/"))
			g.Expect(provider.calls).To(Equal(tc.wantRetrieves))
		})
	}
}
