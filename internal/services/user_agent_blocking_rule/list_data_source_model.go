// File generated from our OpenAPI spec by Stainless. See CONTRIBUTING.md for details.

package user_agent_blocking_rule

import (
	"context"

	"github.com/cloudflare/cloudflare-go/v5"
	"github.com/cloudflare/cloudflare-go/v5/firewall"
	"github.com/cloudflare/terraform-provider-cloudflare/internal/customfield"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

type UserAgentBlockingRulesResultListDataSourceEnvelope struct {
	Result customfield.NestedObjectList[UserAgentBlockingRulesResultDataSourceModel] `json:"result,computed"`
}

type UserAgentBlockingRulesDataSourceModel struct {
	ZoneID      types.String                                                              `tfsdk:"zone_id" path:"zone_id,required"`
	Description types.String                                                              `tfsdk:"description" query:"description,optional"`
	Paused      types.Bool                                                                `tfsdk:"paused" query:"paused,optional"`
	UserAgent   types.String                                                              `tfsdk:"user_agent" query:"user_agent,optional"`
	MaxItems    types.Int64                                                               `tfsdk:"max_items"`
	Result      customfield.NestedObjectList[UserAgentBlockingRulesResultDataSourceModel] `tfsdk:"result"`
}

func (m *UserAgentBlockingRulesDataSourceModel) toListParams(_ context.Context) (params firewall.UARuleListParams, diags diag.Diagnostics) {
	params = firewall.UARuleListParams{
		ZoneID: cloudflare.F(m.ZoneID.ValueString()),
	}

	if !m.Description.IsNull() {
		params.Description = cloudflare.F(m.Description.ValueString())
	}
	if !m.Paused.IsNull() {
		params.Paused = cloudflare.F(m.Paused.ValueBool())
	}
	if !m.UserAgent.IsNull() {
		params.UserAgent = cloudflare.F(m.UserAgent.ValueString())
	}

	return
}

type UserAgentBlockingRulesResultDataSourceModel struct {
	ID            types.String                                                                 `tfsdk:"id" json:"id,computed"`
	Configuration customfield.NestedObject[UserAgentBlockingRulesConfigurationDataSourceModel] `tfsdk:"configuration" json:"configuration,computed"`
	Description   types.String                                                                 `tfsdk:"description" json:"description,computed"`
	Mode          types.String                                                                 `tfsdk:"mode" json:"mode,computed"`
	Paused        types.Bool                                                                   `tfsdk:"paused" json:"paused,computed"`
}

type UserAgentBlockingRulesConfigurationDataSourceModel struct {
	Target types.String `tfsdk:"target" json:"target,computed"`
	Value  types.String `tfsdk:"value" json:"value,computed"`
}
