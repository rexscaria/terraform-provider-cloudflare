// File generated from our OpenAPI spec by Stainless. See CONTRIBUTING.md for details.

package custom_ssl

import (
	"github.com/cloudflare/terraform-provider-cloudflare/internal/apijson"
	"github.com/cloudflare/terraform-provider-cloudflare/internal/customfield"
	"github.com/hashicorp/terraform-plugin-framework-timetypes/timetypes"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

type CustomSSLResultEnvelope struct {
	Result CustomSSLModel `json:"result"`
}

type CustomSSLModel struct {
	ID              types.String                                          `tfsdk:"id" json:"id,computed"`
	ZoneID          types.String                                          `tfsdk:"zone_id" path:"zone_id,required"`
	Type            types.String                                          `tfsdk:"type" json:"type,computed_optional,no_refresh"`
	Certificate     types.String                                          `tfsdk:"certificate" json:"certificate,required,no_refresh"`
	PrivateKey      types.String                                          `tfsdk:"private_key" json:"private_key,required,no_refresh"`
	Policy          types.String                                          `tfsdk:"policy" json:"policy,optional"`
	GeoRestrictions *CustomSSLGeoRestrictionsModel                        `tfsdk:"geo_restrictions" json:"geo_restrictions,optional"`
	BundleMethod    types.String                                          `tfsdk:"bundle_method" json:"bundle_method,computed_optional"`
	ExpiresOn       timetypes.RFC3339                                     `tfsdk:"expires_on" json:"expires_on,computed" format:"date-time"`
	Issuer          types.String                                          `tfsdk:"issuer" json:"issuer,computed"`
	ModifiedOn      timetypes.RFC3339                                     `tfsdk:"modified_on" json:"modified_on,computed" format:"date-time"`
	Priority        types.Float64                                         `tfsdk:"priority" json:"priority,computed"`
	Signature       types.String                                          `tfsdk:"signature" json:"signature,computed"`
	Status          types.String                                          `tfsdk:"status" json:"status,computed"`
	UploadedOn      timetypes.RFC3339                                     `tfsdk:"uploaded_on" json:"uploaded_on,computed" format:"date-time"`
	Hosts           customfield.List[types.String]                        `tfsdk:"hosts" json:"hosts,computed"`
	KeylessServer   customfield.NestedObject[CustomSSLKeylessServerModel] `tfsdk:"keyless_server" json:"keyless_server,computed"`
}

func (m CustomSSLModel) MarshalJSON() (data []byte, err error) {
	return apijson.MarshalRoot(m)
}

func (m CustomSSLModel) MarshalJSONForUpdate(state CustomSSLModel) (data []byte, err error) {
	return apijson.MarshalForPatch(m, state)
}

type CustomSSLGeoRestrictionsModel struct {
	Label types.String `tfsdk:"label" json:"label,optional"`
}

type CustomSSLKeylessServerModel struct {
	ID          types.String                                                `tfsdk:"id" json:"id,computed"`
	CreatedOn   timetypes.RFC3339                                           `tfsdk:"created_on" json:"created_on,computed" format:"date-time"`
	Enabled     types.Bool                                                  `tfsdk:"enabled" json:"enabled,computed"`
	Host        types.String                                                `tfsdk:"host" json:"host,computed"`
	ModifiedOn  timetypes.RFC3339                                           `tfsdk:"modified_on" json:"modified_on,computed" format:"date-time"`
	Name        types.String                                                `tfsdk:"name" json:"name,computed"`
	Permissions customfield.List[types.String]                              `tfsdk:"permissions" json:"permissions,computed"`
	Port        types.Float64                                               `tfsdk:"port" json:"port,computed"`
	Status      types.String                                                `tfsdk:"status" json:"status,computed"`
	Tunnel      customfield.NestedObject[CustomSSLKeylessServerTunnelModel] `tfsdk:"tunnel" json:"tunnel,computed"`
}

type CustomSSLKeylessServerTunnelModel struct {
	PrivateIP types.String `tfsdk:"private_ip" json:"private_ip,computed"`
	VnetID    types.String `tfsdk:"vnet_id" json:"vnet_id,computed"`
}
