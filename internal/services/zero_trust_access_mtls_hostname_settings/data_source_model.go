// File generated from our OpenAPI spec by Stainless. See CONTRIBUTING.md for details.

package zero_trust_access_mtls_hostname_settings

import (
	"context"

	"github.com/cloudflare/cloudflare-go/v5"
	"github.com/cloudflare/cloudflare-go/v5/zero_trust"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

type ZeroTrustAccessMTLSHostnameSettingsResultDataSourceEnvelope struct {
	Result ZeroTrustAccessMTLSHostnameSettingsDataSourceModel `json:"result,computed"`
}

type ZeroTrustAccessMTLSHostnameSettingsDataSourceModel struct {
	AccountID                   types.String `tfsdk:"account_id" path:"account_id,optional"`
	ZoneID                      types.String `tfsdk:"zone_id" path:"zone_id,optional"`
	ChinaNetwork                types.Bool   `tfsdk:"china_network" json:"china_network,computed"`
	ClientCertificateForwarding types.Bool   `tfsdk:"client_certificate_forwarding" json:"client_certificate_forwarding,computed"`
	Hostname                    types.String `tfsdk:"hostname" json:"hostname,computed"`
}

func (m *ZeroTrustAccessMTLSHostnameSettingsDataSourceModel) toReadParams(_ context.Context) (params zero_trust.AccessCertificateSettingGetParams, diags diag.Diagnostics) {
	params = zero_trust.AccessCertificateSettingGetParams{}

	if !m.AccountID.IsNull() {
		params.AccountID = cloudflare.F(m.AccountID.ValueString())
	} else {
		params.ZoneID = cloudflare.F(m.ZoneID.ValueString())
	}

	return
}
