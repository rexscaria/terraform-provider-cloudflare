// File generated from our OpenAPI spec by Stainless. See CONTRIBUTING.md for details.

package spectrum_application

import (
	"context"

	"github.com/cloudflare/cloudflare-go/v5"
	"github.com/cloudflare/cloudflare-go/v5/spectrum"
	"github.com/cloudflare/terraform-provider-cloudflare/internal/customfield"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

type SpectrumApplicationsResultListDataSourceEnvelope struct {
	Result customfield.NestedObjectList[SpectrumApplicationsResultDataSourceModel] `json:"result,computed"`
}

type SpectrumApplicationsDataSourceModel struct {
	ZoneID    types.String                                                            `tfsdk:"zone_id" path:"zone_id,required"`
	Direction types.String                                                            `tfsdk:"direction" query:"direction,computed_optional"`
	Order     types.String                                                            `tfsdk:"order" query:"order,computed_optional"`
	MaxItems  types.Int64                                                             `tfsdk:"max_items"`
	Result    customfield.NestedObjectList[SpectrumApplicationsResultDataSourceModel] `tfsdk:"result"`
}

func (m *SpectrumApplicationsDataSourceModel) toListParams(_ context.Context) (params spectrum.AppListParams, diags diag.Diagnostics) {
	params = spectrum.AppListParams{
		ZoneID: cloudflare.F(m.ZoneID.ValueString()),
	}

	if !m.Direction.IsNull() {
		params.Direction = cloudflare.F(spectrum.AppListParamsDirection(m.Direction.ValueString()))
	}
	if !m.Order.IsNull() {
		params.Order = cloudflare.F(spectrum.AppListParamsOrder(m.Order.ValueString()))
	}

	return
}

type SpectrumApplicationsResultDataSourceModel struct {
}
