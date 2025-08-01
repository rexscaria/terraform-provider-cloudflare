// File generated from our OpenAPI spec by Stainless. See CONTRIBUTING.md for details.

package workers_route

import (
	"context"

	"github.com/cloudflare/cloudflare-go/v5"
	"github.com/cloudflare/cloudflare-go/v5/workers"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

type WorkersRouteResultDataSourceEnvelope struct {
	Result WorkersRouteDataSourceModel `json:"result,computed"`
}

type WorkersRouteDataSourceModel struct {
	ID      types.String `tfsdk:"id" path:"route_id,computed"`
	RouteID types.String `tfsdk:"route_id" path:"route_id,optional"`
	ZoneID  types.String `tfsdk:"zone_id" path:"zone_id,required"`
	Pattern types.String `tfsdk:"pattern" json:"pattern,computed"`
	Script  types.String `tfsdk:"script" json:"script,computed"`
}

func (m *WorkersRouteDataSourceModel) toReadParams(_ context.Context) (params workers.RouteGetParams, diags diag.Diagnostics) {
	params = workers.RouteGetParams{
		ZoneID: cloudflare.F(m.ZoneID.ValueString()),
	}

	return
}
