// File generated from our OpenAPI spec by Stainless. See CONTRIBUTING.md for details.

package origin_ca_certificate

import (
	"context"

	"github.com/cloudflare/cloudflare-go/v5"
	"github.com/cloudflare/cloudflare-go/v5/origin_ca_certificates"
	"github.com/cloudflare/terraform-provider-cloudflare/internal/customfield"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

type OriginCACertificatesResultListDataSourceEnvelope struct {
	Result customfield.NestedObjectList[OriginCACertificatesResultDataSourceModel] `json:"result,computed"`
}

type OriginCACertificatesDataSourceModel struct {
	ZoneID   types.String                                                            `tfsdk:"zone_id" query:"zone_id,required"`
	Limit    types.Int64                                                             `tfsdk:"limit" query:"limit,optional"`
	Offset   types.Int64                                                             `tfsdk:"offset" query:"offset,optional"`
	MaxItems types.Int64                                                             `tfsdk:"max_items"`
	Result   customfield.NestedObjectList[OriginCACertificatesResultDataSourceModel] `tfsdk:"result"`
}

func (m *OriginCACertificatesDataSourceModel) toListParams(_ context.Context) (params origin_ca_certificates.OriginCACertificateListParams, diags diag.Diagnostics) {
	params = origin_ca_certificates.OriginCACertificateListParams{
		ZoneID: cloudflare.F(m.ZoneID.ValueString()),
	}

	if !m.Limit.IsNull() {
		params.Limit = cloudflare.F(m.Limit.ValueInt64())
	}
	if !m.Offset.IsNull() {
		params.Offset = cloudflare.F(m.Offset.ValueInt64())
	}

	return
}

type OriginCACertificatesResultDataSourceModel struct {
	Csr               types.String                   `tfsdk:"csr" json:"csr,computed"`
	Hostnames         customfield.List[types.String] `tfsdk:"hostnames" json:"hostnames,computed"`
	RequestType       types.String                   `tfsdk:"request_type" json:"request_type,computed"`
	RequestedValidity types.Float64                  `tfsdk:"requested_validity" json:"requested_validity,computed"`
	ID                types.String                   `tfsdk:"id" json:"id,computed"`
	Certificate       types.String                   `tfsdk:"certificate" json:"certificate,computed"`
	ExpiresOn         types.String                   `tfsdk:"expires_on" json:"expires_on,computed"`
}
