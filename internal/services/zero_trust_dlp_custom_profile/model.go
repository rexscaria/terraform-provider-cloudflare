// File generated from our OpenAPI spec by Stainless. See CONTRIBUTING.md for details.

package zero_trust_dlp_custom_profile

import (
	"github.com/cloudflare/terraform-provider-cloudflare/internal/apijson"
	"github.com/hashicorp/terraform-plugin-framework-timetypes/timetypes"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

type ZeroTrustDLPCustomProfileResultEnvelope struct {
	Result ZeroTrustDLPCustomProfileModel `json:"result"`
}

type ZeroTrustDLPCustomProfileModel struct {
	ID                  types.String                                    `tfsdk:"id" json:"id,computed"`
	AccountID           types.String                                    `tfsdk:"account_id" path:"account_id,required"`
	Name                types.String                                    `tfsdk:"name" json:"name,required"`
	Description         types.String                                    `tfsdk:"description" json:"description,optional"`
	ContextAwareness    *ZeroTrustDLPCustomProfileContextAwarenessModel `tfsdk:"context_awareness" json:"context_awareness,optional"`
	Entries             *[]*ZeroTrustDLPCustomProfileEntriesModel       `tfsdk:"entries" json:"entries,optional"`
	SharedEntries       *[]*ZeroTrustDLPCustomProfileSharedEntriesModel `tfsdk:"shared_entries" json:"shared_entries,optional,no_refresh"`
	AIContextEnabled    types.Bool                                      `tfsdk:"ai_context_enabled" json:"ai_context_enabled,computed_optional"`
	AllowedMatchCount   types.Int64                                     `tfsdk:"allowed_match_count" json:"allowed_match_count,computed_optional"`
	ConfidenceThreshold types.String                                    `tfsdk:"confidence_threshold" json:"confidence_threshold,computed_optional"`
	OCREnabled          types.Bool                                      `tfsdk:"ocr_enabled" json:"ocr_enabled,computed_optional"`
	CreatedAt           timetypes.RFC3339                               `tfsdk:"created_at" json:"created_at,computed" format:"date-time"`
	OpenAccess          types.Bool                                      `tfsdk:"open_access" json:"open_access,computed"`
	Type                types.String                                    `tfsdk:"type" json:"type,computed"`
	UpdatedAt           timetypes.RFC3339                               `tfsdk:"updated_at" json:"updated_at,computed" format:"date-time"`
}

func (m ZeroTrustDLPCustomProfileModel) MarshalJSON() (data []byte, err error) {
	return apijson.MarshalRoot(m)
}

func (m ZeroTrustDLPCustomProfileModel) MarshalJSONForUpdate(state ZeroTrustDLPCustomProfileModel) (data []byte, err error) {
	return apijson.MarshalForUpdate(m, state)
}

type ZeroTrustDLPCustomProfileContextAwarenessModel struct {
	Enabled types.Bool                                          `tfsdk:"enabled" json:"enabled,required"`
	Skip    *ZeroTrustDLPCustomProfileContextAwarenessSkipModel `tfsdk:"skip" json:"skip,required"`
}

type ZeroTrustDLPCustomProfileContextAwarenessSkipModel struct {
	Files types.Bool `tfsdk:"files" json:"files,required"`
}

type ZeroTrustDLPCustomProfileEntriesModel struct {
	Enabled types.Bool                                    `tfsdk:"enabled" json:"enabled,required"`
	EntryID types.String                                  `tfsdk:"entry_id" json:"entry_id,optional,no_refresh"`
	Name    types.String                                  `tfsdk:"name" json:"name,required"`
	Pattern *ZeroTrustDLPCustomProfileEntriesPatternModel `tfsdk:"pattern" json:"pattern,required"`
}

type ZeroTrustDLPCustomProfileEntriesPatternModel struct {
	Regex      types.String `tfsdk:"regex" json:"regex,required"`
	Validation types.String `tfsdk:"validation" json:"validation,optional"`
}

type ZeroTrustDLPCustomProfileSharedEntriesModel struct {
	Enabled   types.Bool   `tfsdk:"enabled" json:"enabled,required"`
	EntryID   types.String `tfsdk:"entry_id" json:"entry_id,required"`
	EntryType types.String `tfsdk:"entry_type" json:"entry_type,required"`
}
