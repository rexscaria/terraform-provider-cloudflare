// File generated from our OpenAPI spec by Stainless. See CONTRIBUTING.md for details.

package zero_trust_gateway_certificate

import (
	"context"

	"github.com/cloudflare/cloudflare-go/v5"
	"github.com/cloudflare/cloudflare-go/v5/zero_trust"
	"github.com/hashicorp/terraform-plugin-framework-timetypes/timetypes"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

type ZeroTrustGatewayCertificateResultDataSourceEnvelope struct {
	Result ZeroTrustGatewayCertificateDataSourceModel `json:"result,computed"`
}

type ZeroTrustGatewayCertificateDataSourceModel struct {
	ID            types.String      `tfsdk:"id" path:"certificate_id,computed"`
	CertificateID types.String      `tfsdk:"certificate_id" path:"certificate_id,optional"`
	AccountID     types.String      `tfsdk:"account_id" path:"account_id,required"`
	BindingStatus types.String      `tfsdk:"binding_status" json:"binding_status,computed"`
	Certificate   types.String      `tfsdk:"certificate" json:"certificate,computed"`
	CreatedAt     timetypes.RFC3339 `tfsdk:"created_at" json:"created_at,computed" format:"date-time"`
	ExpiresOn     timetypes.RFC3339 `tfsdk:"expires_on" json:"expires_on,computed" format:"date-time"`
	Fingerprint   types.String      `tfsdk:"fingerprint" json:"fingerprint,computed"`
	InUse         types.Bool        `tfsdk:"in_use" json:"in_use,computed"`
	IssuerOrg     types.String      `tfsdk:"issuer_org" json:"issuer_org,computed"`
	IssuerRaw     types.String      `tfsdk:"issuer_raw" json:"issuer_raw,computed"`
	Type          types.String      `tfsdk:"type" json:"type,computed"`
	UpdatedAt     timetypes.RFC3339 `tfsdk:"updated_at" json:"updated_at,computed" format:"date-time"`
	UploadedOn    timetypes.RFC3339 `tfsdk:"uploaded_on" json:"uploaded_on,computed" format:"date-time"`
}

func (m *ZeroTrustGatewayCertificateDataSourceModel) toReadParams(_ context.Context) (params zero_trust.GatewayCertificateGetParams, diags diag.Diagnostics) {
	params = zero_trust.GatewayCertificateGetParams{
		AccountID: cloudflare.F(m.AccountID.ValueString()),
	}

	return
}
