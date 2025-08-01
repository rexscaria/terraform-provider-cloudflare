// File generated from our OpenAPI spec by Stainless. See CONTRIBUTING.md for details.

package list_item

import (
	"context"
	"fmt"

	"github.com/cloudflare/cloudflare-go/v5"
	"github.com/hashicorp/terraform-plugin-framework/datasource"
)

type ListItemDataSource struct {
	client *cloudflare.Client
}

var _ datasource.DataSourceWithConfigure = (*ListItemDataSource)(nil)

func NewListItemDataSource() datasource.DataSource {
	return &ListItemDataSource{}
}

func (d *ListItemDataSource) Metadata(ctx context.Context, req datasource.MetadataRequest, resp *datasource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_list_item"
}

func (d *ListItemDataSource) Configure(ctx context.Context, req datasource.ConfigureRequest, resp *datasource.ConfigureResponse) {
	if req.ProviderData == nil {
		return
	}

	client, ok := req.ProviderData.(*cloudflare.Client)

	if !ok {
		resp.Diagnostics.AddError(
			"unexpected resource configure type",
			fmt.Sprintf("Expected *cloudflare.Client, got: %T. Please report this issue to the provider developers.", req.ProviderData),
		)

		return
	}

	d.client = client
}

func (d *ListItemDataSource) Read(ctx context.Context, req datasource.ReadRequest, resp *datasource.ReadResponse) {
	var data *ListItemDataSourceModel

	// resp.Diagnostics.Append(req.Config.Get(ctx, &data)...)

	// if resp.Diagnostics.HasError() {
	// 	return
	// }

	// params, diags := data.toReadParams(ctx)
	// resp.Diagnostics.Append(diags...)
	// if resp.Diagnostics.HasError() {
	// 	return
	// }

	// res := new(http.Response)
	// env := ListItemResultDataSourceEnvelope{*data}
	// _, err := d.client.Rules.Lists.Items.Get(
	// 	ctx,
	// 	data.ListID.ValueString(),
	// 	data.ItemID.ValueString(),
	// 	params,
	// 	option.WithResponseBodyInto(&res),
	// 	option.WithMiddleware(logging.Middleware(ctx)),
	// )
	// if err != nil {
	// 	resp.Diagnostics.AddError("failed to make http request", err.Error())
	// 	return
	// }
	// bytes, _ := io.ReadAll(res.Body)
	// err = apijson.UnmarshalComputed(bytes, &env)
	// if err != nil {
	// 	resp.Diagnostics.AddError("failed to deserialize http request", err.Error())
	// 	return
	// }
	// data = &env.Result

	resp.Diagnostics.Append(resp.State.Set(ctx, &data)...)
}
