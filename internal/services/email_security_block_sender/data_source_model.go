// File generated from our OpenAPI spec by Stainless. See CONTRIBUTING.md for details.

package email_security_block_sender

import (
	"context"

	"github.com/cloudflare/cloudflare-go/v5"
	"github.com/cloudflare/cloudflare-go/v5/email_security"
	"github.com/hashicorp/terraform-plugin-framework-timetypes/timetypes"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

type EmailSecurityBlockSenderResultDataSourceEnvelope struct {
	Result EmailSecurityBlockSenderDataSourceModel `json:"result,computed"`
}

type EmailSecurityBlockSenderDataSourceModel struct {
	ID           types.Int64                                       `tfsdk:"id" path:"pattern_id,computed"`
	PatternID    types.Int64                                       `tfsdk:"pattern_id" path:"pattern_id,optional"`
	AccountID    types.String                                      `tfsdk:"account_id" path:"account_id,required"`
	Comments     types.String                                      `tfsdk:"comments" json:"comments,computed"`
	CreatedAt    timetypes.RFC3339                                 `tfsdk:"created_at" json:"created_at,computed" format:"date-time"`
	IsRegex      types.Bool                                        `tfsdk:"is_regex" json:"is_regex,computed"`
	LastModified timetypes.RFC3339                                 `tfsdk:"last_modified" json:"last_modified,computed" format:"date-time"`
	Pattern      types.String                                      `tfsdk:"pattern" json:"pattern,computed"`
	PatternType  types.String                                      `tfsdk:"pattern_type" json:"pattern_type,computed"`
	Filter       *EmailSecurityBlockSenderFindOneByDataSourceModel `tfsdk:"filter"`
}

func (m *EmailSecurityBlockSenderDataSourceModel) toReadParams(_ context.Context) (params email_security.SettingBlockSenderGetParams, diags diag.Diagnostics) {
	params = email_security.SettingBlockSenderGetParams{
		AccountID: cloudflare.F(m.AccountID.ValueString()),
	}

	return
}

func (m *EmailSecurityBlockSenderDataSourceModel) toListParams(_ context.Context) (params email_security.SettingBlockSenderListParams, diags diag.Diagnostics) {
	params = email_security.SettingBlockSenderListParams{
		AccountID: cloudflare.F(m.AccountID.ValueString()),
	}

	if !m.Filter.Direction.IsNull() {
		params.Direction = cloudflare.F(email_security.SettingBlockSenderListParamsDirection(m.Filter.Direction.ValueString()))
	}
	if !m.Filter.Order.IsNull() {
		params.Order = cloudflare.F(email_security.SettingBlockSenderListParamsOrder(m.Filter.Order.ValueString()))
	}
	if !m.Filter.Pattern.IsNull() {
		params.Pattern = cloudflare.F(m.Filter.Pattern.ValueString())
	}
	if !m.Filter.PatternType.IsNull() {
		params.PatternType = cloudflare.F(email_security.SettingBlockSenderListParamsPatternType(m.Filter.PatternType.ValueString()))
	}
	if !m.Filter.Search.IsNull() {
		params.Search = cloudflare.F(m.Filter.Search.ValueString())
	}

	return
}

type EmailSecurityBlockSenderFindOneByDataSourceModel struct {
	Direction   types.String `tfsdk:"direction" query:"direction,optional"`
	Order       types.String `tfsdk:"order" query:"order,optional"`
	Pattern     types.String `tfsdk:"pattern" query:"pattern,optional"`
	PatternType types.String `tfsdk:"pattern_type" query:"pattern_type,optional"`
	Search      types.String `tfsdk:"search" query:"search,optional"`
}
