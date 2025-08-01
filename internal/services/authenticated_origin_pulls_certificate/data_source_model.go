// File generated from our OpenAPI spec by Stainless. See CONTRIBUTING.md for details.

package authenticated_origin_pulls_certificate

import (
	"context"

	"github.com/cloudflare/cloudflare-go/v5"
	"github.com/cloudflare/cloudflare-go/v5/origin_tls_client_auth"
	"github.com/hashicorp/terraform-plugin-framework-timetypes/timetypes"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

type AuthenticatedOriginPullsCertificateResultDataSourceEnvelope struct {
	Result AuthenticatedOriginPullsCertificateDataSourceModel `json:"result,computed"`
}

type AuthenticatedOriginPullsCertificateDataSourceModel struct {
	CertificateID types.String      `tfsdk:"certificate_id" path:"certificate_id,required"`
	ZoneID        types.String      `tfsdk:"zone_id" path:"zone_id,required"`
	Certificate   types.String      `tfsdk:"certificate" json:"certificate,computed"`
	Enabled       types.Bool        `tfsdk:"enabled" json:"enabled,computed"`
	ExpiresOn     timetypes.RFC3339 `tfsdk:"expires_on" json:"expires_on,computed" format:"date-time"`
	ID            types.String      `tfsdk:"id" json:"id,computed"`
	Issuer        types.String      `tfsdk:"issuer" json:"issuer,computed"`
	PrivateKey    types.String      `tfsdk:"private_key" json:"private_key,computed"`
	Signature     types.String      `tfsdk:"signature" json:"signature,computed"`
	Status        types.String      `tfsdk:"status" json:"status,computed"`
	UploadedOn    timetypes.RFC3339 `tfsdk:"uploaded_on" json:"uploaded_on,computed" format:"date-time"`
}

func (m *AuthenticatedOriginPullsCertificateDataSourceModel) toReadParams(_ context.Context) (params origin_tls_client_auth.OriginTLSClientAuthGetParams, diags diag.Diagnostics) {
	params = origin_tls_client_auth.OriginTLSClientAuthGetParams{
		ZoneID: cloudflare.F(m.ZoneID.ValueString()),
	}

	return
}
