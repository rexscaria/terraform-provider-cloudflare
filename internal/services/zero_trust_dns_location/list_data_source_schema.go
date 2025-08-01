// File generated from our OpenAPI spec by Stainless. See CONTRIBUTING.md for details.

package zero_trust_dns_location

import (
	"context"

	"github.com/cloudflare/terraform-provider-cloudflare/internal/customfield"
	"github.com/hashicorp/terraform-plugin-framework-timetypes/timetypes"
	"github.com/hashicorp/terraform-plugin-framework-validators/int64validator"
	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/datasource/schema"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
)

var _ datasource.DataSourceWithConfigValidators = (*ZeroTrustDNSLocationsDataSource)(nil)

func ListDataSourceSchema(ctx context.Context) schema.Schema {
	return schema.Schema{
		Attributes: map[string]schema.Attribute{
			"account_id": schema.StringAttribute{
				Required: true,
			},
			"max_items": schema.Int64Attribute{
				Description: "Max items to fetch, default: 1000",
				Optional:    true,
				Validators: []validator.Int64{
					int64validator.AtLeast(0),
				},
			},
			"result": schema.ListNestedAttribute{
				Description: "The items returned by the data source",
				Computed:    true,
				CustomType:  customfield.NewNestedObjectListType[ZeroTrustDNSLocationsResultDataSourceModel](ctx),
				NestedObject: schema.NestedAttributeObject{
					Attributes: map[string]schema.Attribute{
						"id": schema.StringAttribute{
							Computed: true,
						},
						"client_default": schema.BoolAttribute{
							Description: "True if the location is the default location.",
							Computed:    true,
						},
						"created_at": schema.StringAttribute{
							Computed:   true,
							CustomType: timetypes.RFC3339Type{},
						},
						"dns_destination_ips_id": schema.StringAttribute{
							Description: "The identifier of the pair of IPv4 addresses assigned to this location.",
							Computed:    true,
						},
						"dns_destination_ipv6_block_id": schema.StringAttribute{
							Description: "The uuid identifier of the IPv6 block brought to the gateway, so that this location's IPv6 address is allocated from the Bring Your Own Ipv6(BYOIPv6) block and not from the standard Cloudflare IPv6 block.",
							Computed:    true,
						},
						"doh_subdomain": schema.StringAttribute{
							Description: "The DNS over HTTPS domain to send DNS requests to. This field is auto-generated by Gateway.",
							Computed:    true,
						},
						"ecs_support": schema.BoolAttribute{
							Description: "True if the location needs to resolve EDNS queries.",
							Computed:    true,
						},
						"endpoints": schema.SingleNestedAttribute{
							Description: "The destination endpoints configured for this location. When updating a location, if this field is absent or set with null, the endpoints configuration remains unchanged.",
							Computed:    true,
							CustomType:  customfield.NewNestedObjectType[ZeroTrustDNSLocationsEndpointsDataSourceModel](ctx),
							Attributes: map[string]schema.Attribute{
								"doh": schema.SingleNestedAttribute{
									Computed:   true,
									CustomType: customfield.NewNestedObjectType[ZeroTrustDNSLocationsEndpointsDOHDataSourceModel](ctx),
									Attributes: map[string]schema.Attribute{
										"enabled": schema.BoolAttribute{
											Description: "True if the endpoint is enabled for this location.",
											Computed:    true,
										},
										"networks": schema.ListNestedAttribute{
											Description: "A list of allowed source IP network ranges for this endpoint. When empty, all source IPs are allowed. A non-empty list is only effective if the endpoint is enabled for this location.",
											Computed:    true,
											CustomType:  customfield.NewNestedObjectListType[ZeroTrustDNSLocationsEndpointsDOHNetworksDataSourceModel](ctx),
											NestedObject: schema.NestedAttributeObject{
												Attributes: map[string]schema.Attribute{
													"network": schema.StringAttribute{
														Description: "The IP address or IP CIDR.",
														Computed:    true,
													},
												},
											},
										},
										"require_token": schema.BoolAttribute{
											Description: "True if the endpoint requires [user identity](https://developers.cloudflare.com/cloudflare-one/connections/connect-devices/agentless/dns/dns-over-https/#filter-doh-requests-by-user) authentication.",
											Computed:    true,
										},
									},
								},
								"dot": schema.SingleNestedAttribute{
									Computed:   true,
									CustomType: customfield.NewNestedObjectType[ZeroTrustDNSLocationsEndpointsDOTDataSourceModel](ctx),
									Attributes: map[string]schema.Attribute{
										"enabled": schema.BoolAttribute{
											Description: "True if the endpoint is enabled for this location.",
											Computed:    true,
										},
										"networks": schema.ListNestedAttribute{
											Description: "A list of allowed source IP network ranges for this endpoint. When empty, all source IPs are allowed. A non-empty list is only effective if the endpoint is enabled for this location.",
											Computed:    true,
											CustomType:  customfield.NewNestedObjectListType[ZeroTrustDNSLocationsEndpointsDOTNetworksDataSourceModel](ctx),
											NestedObject: schema.NestedAttributeObject{
												Attributes: map[string]schema.Attribute{
													"network": schema.StringAttribute{
														Description: "The IP address or IP CIDR.",
														Computed:    true,
													},
												},
											},
										},
									},
								},
								"ipv4": schema.SingleNestedAttribute{
									Computed:   true,
									CustomType: customfield.NewNestedObjectType[ZeroTrustDNSLocationsEndpointsIPV4DataSourceModel](ctx),
									Attributes: map[string]schema.Attribute{
										"enabled": schema.BoolAttribute{
											Description: "True if the endpoint is enabled for this location.",
											Computed:    true,
										},
									},
								},
								"ipv6": schema.SingleNestedAttribute{
									Computed:   true,
									CustomType: customfield.NewNestedObjectType[ZeroTrustDNSLocationsEndpointsIPV6DataSourceModel](ctx),
									Attributes: map[string]schema.Attribute{
										"enabled": schema.BoolAttribute{
											Description: "True if the endpoint is enabled for this location.",
											Computed:    true,
										},
										"networks": schema.ListNestedAttribute{
											Description: "A list of allowed source IPv6 network ranges for this endpoint. When empty, all source IPs are allowed. A non-empty list is only effective if the endpoint is enabled for this location.",
											Computed:    true,
											CustomType:  customfield.NewNestedObjectListType[ZeroTrustDNSLocationsEndpointsIPV6NetworksDataSourceModel](ctx),
											NestedObject: schema.NestedAttributeObject{
												Attributes: map[string]schema.Attribute{
													"network": schema.StringAttribute{
														Description: "The IPv6 address or IPv6 CIDR.",
														Computed:    true,
													},
												},
											},
										},
									},
								},
							},
						},
						"ip": schema.StringAttribute{
							Description: "IPV6 destination ip assigned to this location. DNS requests sent to this IP will counted as the request under this location. This field is auto-generated by Gateway.",
							Computed:    true,
						},
						"ipv4_destination": schema.StringAttribute{
							Description: "The primary destination IPv4 address from the pair identified by the dns_destination_ips_id. This field is read-only.",
							Computed:    true,
						},
						"ipv4_destination_backup": schema.StringAttribute{
							Description: "The backup destination IPv4 address from the pair identified by the dns_destination_ips_id. This field is read-only.",
							Computed:    true,
						},
						"name": schema.StringAttribute{
							Description: "The name of the location.",
							Computed:    true,
						},
						"networks": schema.ListNestedAttribute{
							Description: "A list of network ranges that requests from this location would originate from. A non-empty list is only effective if the ipv4 endpoint is enabled for this location.",
							Computed:    true,
							CustomType:  customfield.NewNestedObjectListType[ZeroTrustDNSLocationsNetworksDataSourceModel](ctx),
							NestedObject: schema.NestedAttributeObject{
								Attributes: map[string]schema.Attribute{
									"network": schema.StringAttribute{
										Description: "The IPv4 address or IPv4 CIDR. IPv4 CIDRs are limited to a maximum of /24.",
										Computed:    true,
									},
								},
							},
						},
						"updated_at": schema.StringAttribute{
							Computed:   true,
							CustomType: timetypes.RFC3339Type{},
						},
					},
				},
			},
		},
	}
}

func (d *ZeroTrustDNSLocationsDataSource) Schema(ctx context.Context, req datasource.SchemaRequest, resp *datasource.SchemaResponse) {
	resp.Schema = ListDataSourceSchema(ctx)
}

func (d *ZeroTrustDNSLocationsDataSource) ConfigValidators(_ context.Context) []datasource.ConfigValidator {
	return []datasource.ConfigValidator{}
}
