package gcloud

import (
	"context"
	"fmt"
	"strings"

	"cloud.google.com/go/storage"
	"github.com/hashicorp/terraform/backend"
	"github.com/hashicorp/terraform/helper/pathorcontents"
	"github.com/hashicorp/terraform/helper/schema"
	googleContext "golang.org/x/net/context"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"
	"google.golang.org/api/option"
)

type Backend struct {
	*schema.Backend

	storageClient  *storage.Client
	storageContext googleContext.Context

	bucketName string
	stateDir   string
}

func New() backend.Backend {
	be := &Backend{}
	be.Backend = &schema.Backend{
		ConfigureFunc: be.configure,
		Schema: map[string]*schema.Schema{
			"bucket": {
				Type:        schema.TypeString,
				Required:    true,
				Description: "The name of the Google Cloud Storage bucket",
			},

			"state_dir": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "The directory where state files will be saved inside the bucket",
			},

			"credentials": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "Google Cloud JSON Account Key",
				Default:     "",
			},
		},
	}

	return be
}

func (b *Backend) configure(ctx context.Context) error {
	if b.storageClient != nil {
		return nil
	}

	// ctx is a background context with the backend config added.
	// Since no context is passed to RemoteClient.Get(), .Lock(), etc. but
	// one is required for calling the GCP API, we're holding on to this
	// context here and re-use it later.
	b.storageContext = ctx

	data := schema.FromContextBackendConfig(b.storageContext)

	b.bucketName = data.Get("bucket").(string)
	b.stateDir = strings.TrimLeft(data.Get("state_dir").(string), "/")

	var tokenSource oauth2.TokenSource

	if credentials := data.Get("credentials").(string); credentials != "" {
		credentialsJson, _, err := pathorcontents.Read(data.Get("credentials").(string))
		if err != nil {
			return fmt.Errorf("Error loading credentials: %v", err)
		}

		jwtConfig, err := google.JWTConfigFromJSON([]byte(credentialsJson), storage.ScopeReadWrite)
		if err != nil {
			return fmt.Errorf("Failed to get Google OAuth2 token: %v", err)
		}

		tokenSource = jwtConfig.TokenSource(b.storageContext)
	} else {
		var err error
		tokenSource, err = google.DefaultTokenSource(b.storageContext, storage.ScopeReadWrite)
		if err != nil {
			return fmt.Errorf("Failed to get Google Application Default Credentials: %v", err)
		}
	}

	client, err := storage.NewClient(b.storageContext, option.WithTokenSource(tokenSource))
	if err != nil {
		return fmt.Errorf("Failed to create Google Storage client: %v", err)
	}

	b.storageClient = client

	return nil
}
