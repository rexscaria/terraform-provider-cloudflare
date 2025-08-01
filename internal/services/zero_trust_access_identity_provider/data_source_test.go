package zero_trust_access_identity_provider_test

import (
	"fmt"
	"os"
	"regexp"
	"testing"

	"github.com/cloudflare/terraform-provider-cloudflare/internal/acctest"
	"github.com/cloudflare/terraform-provider-cloudflare/internal/consts"
	"github.com/cloudflare/terraform-provider-cloudflare/internal/utils"
	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
)

func TestAccCloudflareAccessIdentityProviderDataSource_PreventZoneIdAndAccountIdConflicts(t *testing.T) {
	rnd := utils.GenerateRandomResourceName()
	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { acctest.TestAccPreCheck(t) },
		ProtoV6ProviderFactories: acctest.TestAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config:      testCloudflareAccessIdentityProviderDataSourceConfigConflictingFields(rnd),
				ExpectError: regexp.MustCompile(regexp.QuoteMeta("Exactly one of these attributes must be configured")),
			},
		},
	})
}

func testCloudflareAccessIdentityProviderDataSourceConfigConflictingFields(rnd string) string {
	return fmt.Sprintf(`
data "cloudflare_zero_trust_access_identity_provider" "%[1]s" {
  account_id = "123abc"
  zone_id    = "abc123"
}
`, rnd)
}

func TestAccCloudflareAccessIdentityProviderDataSource_PreventNoInputSpecify(t *testing.T) {
	rnd := utils.GenerateRandomResourceName()
	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { acctest.TestAccPreCheck(t) },
		ProtoV6ProviderFactories: acctest.TestAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config:      testCloudflareAccessIdentityProviderDataSourceNoInput(rnd),
				ExpectError: regexp.MustCompile(regexp.QuoteMeta("Exactly one of these attributes must be configured")),
			},
		},
	})
}

func testCloudflareAccessIdentityProviderDataSourceNoInput(rnd string) string {
	return fmt.Sprintf(`
data "cloudflare_zero_trust_access_identity_provider" "%[1]s" {
}
`, rnd)
}

func TestAccCloudflareAccessIdentityProviderDataSourceNotFound(t *testing.T) {
	t.Skip(`FIXME: "message": "access.api.error.not_found"`)
	accountID := os.Getenv("CLOUDFLARE_ACCOUNT_ID")
	rnd := utils.GenerateRandomResourceName()

	resource.Test(t, resource.TestCase{
		PreCheck: func() {
			acctest.TestAccPreCheck(t)
			acctest.TestAccPreCheck_AccountID(t)
		},
		ProtoV6ProviderFactories: acctest.TestAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config:      testAccCheckCloudflareAccessIdentityProviderDataSource_NotFound(accountID, rnd),
				ExpectError: regexp.MustCompile(`no Access Identity Providers found|no Access Identity Provider matching name`),
			},
		},
	})
}

func testAccCheckCloudflareAccessIdentityProviderDataSource_NotFound(accountID, name string) string {
	return acctest.LoadTestCase("notfound.tf", name, accountID)
}

func TestAccCloudflareAccessIdentityProviderDataSource_GitHub(t *testing.T) {
	t.Skip(`FIXME: Exactly one of these attributes must be configured: [identity_provider_id,filter]`)
	accountID := os.Getenv("CLOUDFLARE_ACCOUNT_ID")
	rnd := utils.GenerateRandomResourceName()

	name := "data.cloudflare_zero_trust_access_identity_provider." + rnd
	resource.Test(t, resource.TestCase{
		PreCheck: func() {
			acctest.TestAccPreCheck(t)
			acctest.TestAccPreCheck_AccountID(t)
		},
		ProtoV6ProviderFactories: acctest.TestAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: testAccCheckCloudflareAccessIdentityProviderDataSourceGitHub(accountID, rnd),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(name, consts.AccountIDSchemaKey, accountID),
					resource.TestCheckResourceAttr(name, "type", "github"),
				),
			},
		},
	})
}

func testAccCheckCloudflareAccessIdentityProviderDataSourceGitHub(accountID, name string) string {
	return acctest.LoadTestCase("accessidentityproviderdatasourcegithub.tf", name, accountID)
}
