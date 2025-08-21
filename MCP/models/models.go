package models

import (
	"context"
	"github.com/mark3labs/mcp-go/mcp"
)

type Tool struct {
	Definition mcp.Tool
	Handler    func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error)
}

// ErrorResponse represents the ErrorResponse schema from the OpenAPI specification
type ErrorResponse struct {
	Errinfo ErrorInfo `json:"errinfo,omitempty"` // Context information for an error used for diagnostics.
	Message string `json:"message,omitempty"` // The error message.
	Txnid string `json:"txnid,omitempty"` // Unique ID for this call.
}

// ProtobufAny represents the ProtobufAny schema from the OpenAPI specification
type ProtobufAny struct {
	Type_url string `json:"type_url,omitempty"`
	Value string `json:"value,omitempty"`
}

// Image represents the Image schema from the OpenAPI specification
type Image struct {
	Digest string `json:"digest,omitempty"` // image digest
	Last_pulled string `json:"last_pulled,omitempty"` // datetime of last pull
	Last_pushed string `json:"last_pushed,omitempty"` // datetime of last push
	Status string `json:"status,omitempty"` // Status of the image
	Variant string `json:"variant,omitempty"` // CPU variant
	Architecture string `json:"architecture,omitempty"` // CPU architecture
	Layers []Layer `json:"layers,omitempty"`
	Os string `json:"os,omitempty"` // operating system
	Os_features string `json:"os_features,omitempty"` // OS features
	Features string `json:"features,omitempty"` // CPU features
	Os_version string `json:"os_version,omitempty"` // OS version
	Size int `json:"size,omitempty"` // size of the image
}

// Scimerror represents the Scimerror schema from the OpenAPI specification
type Scimerror struct {
	Detail string `json:"detail,omitempty"` // Details about why the request failed.
	Schemas []string `json:"schemas,omitempty"`
	Status string `json:"status,omitempty"` // The status code for the response in string format.
}

// GetAuditLogsResponse represents the GetAuditLogsResponse schema from the OpenAPI specification
type GetAuditLogsResponse struct {
	Logs []AuditLog `json:"logs,omitempty"` // List of audit log events.
}

// PostNamespacesDeleteImagesRequest represents the PostNamespacesDeleteImagesRequest schema from the OpenAPI specification
type PostNamespacesDeleteImagesRequest struct {
	Active_from string `json:"active_from,omitempty"` // Sets the time from which an image must have been pushed or pulled to be counted as active. Defaults to 1 month before the current time.
	Dry_run bool `json:"dry_run,omitempty"` // If `true` then will check and return errors and unignored warnings for the deletion request but will not delete any images.
	Ignore_warnings []map[string]interface{} `json:"ignore_warnings,omitempty"` // Warnings to ignore. If a warning is not ignored then no deletions will happen and the warning is returned in the response. These warnings include: - is_active: warning when attempting to delete an image that is marked as active. - current_tag: warning when attempting to delete an image that has one or more current tags in the repository. Warnings can be copied from the response to the request.
	Manifests []map[string]interface{} `json:"manifests,omitempty"` // Image manifests to delete.
}

// UsersLoginRequest represents the UsersLoginRequest schema from the OpenAPI specification
type UsersLoginRequest struct {
	Password string `json:"password"` // The password or personal access token (PAT) of the Docker Hub account to authenticate with.
	Username string `json:"username"` // The username of the Docker Hub account to authenticate with.
}

// Scimschemaparentattribute represents the Scimschemaparentattribute schema from the OpenAPI specification
type Scimschemaparentattribute struct {
	Description string `json:"description,omitempty"`
	Mutability string `json:"mutability,omitempty"`
	Name string `json:"name,omitempty"`
	Returned string `json:"returned,omitempty"`
	Multivalued bool `json:"multiValued,omitempty"`
	Required bool `json:"required,omitempty"`
	TypeField string `json:"type,omitempty"`
	Uniqueness string `json:"uniqueness,omitempty"`
	Caseexact bool `json:"caseExact,omitempty"`
	Subattributes []Scimschemaattribute `json:"subAttributes,omitempty"`
}

// AuditLogActions represents the AuditLogActions schema from the OpenAPI specification
type AuditLogActions struct {
	Actions []AuditLogAction `json:"actions,omitempty"` // List of audit log actions.
	Label string `json:"label,omitempty"` // Grouping label for a particular set of audit log actions.
}

// PostUsers2FALoginErrorResponse represents the PostUsers2FALoginErrorResponse schema from the OpenAPI specification
type PostUsers2FALoginErrorResponse struct {
	Detail string `json:"detail,omitempty"` // Description of the error.
}

// Paginatedtags represents the Paginatedtags schema from the OpenAPI specification
type Paginatedtags struct {
	Next string `json:"next,omitempty"` // link to next page of results if any
	Previous string `json:"previous,omitempty"` // link to previous page of results if any
	Count int `json:"count,omitempty"` // total number of results available across all pages
	Results []Tag `json:"results,omitempty"`
}

// ErrorDetail represents the ErrorDetail schema from the OpenAPI specification
type ErrorDetail struct {
	Detail string `json:"detail,omitempty"` // The error message.
}

// PatchAccessTokenResponse represents the PatchAccessTokenResponse schema from the OpenAPI specification
type PatchAccessTokenResponse struct {
	Token_label string `json:"token_label,omitempty"`
	Client_id string `json:"client_id,omitempty"`
	Created_at string `json:"created_at,omitempty"`
	Creator_ua string `json:"creator_ua,omitempty"`
	Last_used string `json:"last_used,omitempty"`
	Creator_ip string `json:"creator_ip,omitempty"`
	Generated_by string `json:"generated_by,omitempty"`
	Scopes []string `json:"scopes,omitempty"`
	Uuid string `json:"uuid,omitempty"`
	Is_active bool `json:"is_active,omitempty"`
	Token string `json:"token,omitempty"`
}

// GetNamespaceRepositoryImagesSummaryResponse represents the GetNamespaceRepositoryImagesSummaryResponse schema from the OpenAPI specification
type GetNamespaceRepositoryImagesSummaryResponse struct {
	Active_from string `json:"active_from,omitempty"` // Time from which an image must have been pushed or pulled to be counted as active.
	Statistics map[string]interface{} `json:"statistics,omitempty"`
}

// Users2FALoginRequest represents the Users2FALoginRequest schema from the OpenAPI specification
type Users2FALoginRequest struct {
	Code string `json:"code"` // The Time-based One-Time Password of the Docker Hub account to authenticate with.
	Login_2fa_token string `json:"login_2fa_token"` // The intermediate 2FA token returned from `/v2/users/login` API.
}

// Page represents the Page schema from the OpenAPI specification
type Page struct {
	Next string `json:"next,omitempty"` // link to next page of results if any
	Previous string `json:"previous,omitempty"` // link to previous page of results if any
	Count int `json:"count,omitempty"` // total number of results available across all pages
}

// ValueError represents the ValueError schema from the OpenAPI specification
type ValueError struct {
	Fields map[string]interface{} `json:"fields,omitempty"`
	Text string `json:"text,omitempty"`
}

// Scimemail represents the Scimemail schema from the OpenAPI specification
type Scimemail struct {
	Display string `json:"display,omitempty"`
	Primary bool `json:"primary,omitempty"`
	Value string `json:"value,omitempty"`
}

// AuditLog represents the AuditLog schema from the OpenAPI specification
type AuditLog struct {
	Account string `json:"account,omitempty"`
	Action string `json:"action,omitempty"`
	Action_description string `json:"action_description,omitempty"`
	Actor string `json:"actor,omitempty"`
	Data map[string]interface{} `json:"data,omitempty"`
	Name string `json:"name,omitempty"`
	Timestamp string `json:"timestamp,omitempty"`
}

// Scimgroup represents the Scimgroup schema from the OpenAPI specification
type Scimgroup struct {
	Display string `json:"display,omitempty"`
	Value string `json:"value,omitempty"`
}

// Error represents the Error schema from the OpenAPI specification
type Error struct {
	Detail string `json:"detail,omitempty"`
	Message string `json:"message,omitempty"`
}

// GetNamespaceRepositoryImagesResponse represents the GetNamespaceRepositoryImagesResponse schema from the OpenAPI specification
type GetNamespaceRepositoryImagesResponse struct {
	Results []map[string]interface{} `json:"results,omitempty"` // Image details.
	Count int `json:"count,omitempty"` // Total count of images in the repository.
	Next string `json:"next,omitempty"` // Link to the next page with the same query parameters if there are more images.
	Previous string `json:"previous,omitempty"` // Link to the previous page with the same query parameters if not on first page.
}

// PostNamespacesDeleteImagesResponseError represents the PostNamespacesDeleteImagesResponseError schema from the OpenAPI specification
type PostNamespacesDeleteImagesResponseError struct {
	Message string `json:"message,omitempty"` // The error message.
	Txnid string `json:"txnid,omitempty"` // Unique ID for this call.
	Errinfo interface{} `json:"errinfo,omitempty"`
}

// PostUsersLoginErrorResponse represents the PostUsersLoginErrorResponse schema from the OpenAPI specification
type PostUsersLoginErrorResponse struct {
	Login_2fa_token string `json:"login_2fa_token,omitempty"` // Short time lived token to be used on `/v2/users/2fa-login` to complete the authentication. This field is present only if 2FA is enabled.
	Detail string `json:"detail"` // Description of the error.
}

// Scimserviceproviderconfig represents the Scimserviceproviderconfig schema from the OpenAPI specification
type Scimserviceproviderconfig struct {
	Documentationuri string `json:"documentationUri,omitempty"`
	Filter map[string]interface{} `json:"filter,omitempty"`
	Bulk map[string]interface{} `json:"bulk,omitempty"`
	Changepassword map[string]interface{} `json:"changePassword,omitempty"`
	Schemas []string `json:"schemas,omitempty"`
	Sort map[string]interface{} `json:"sort,omitempty"`
	Etag map[string]interface{} `json:"etag,omitempty"`
	Patch interface{} `json:"patch,omitempty"`
	Authenticationschemes map[string]interface{} `json:"authenticationSchemes,omitempty"`
}

// OrgSettings represents the OrgSettings schema from the OpenAPI specification
type OrgSettings struct {
	Restricted_images Restrictedimages `json:"restricted_images,omitempty"`
}

// ErrorInfo represents the ErrorInfo schema from the OpenAPI specification
type ErrorInfo struct {
	Api_call_txnid string `json:"api_call_txnid,omitempty"` // Unique ID for this call.
	Api_call_docker_id string `json:"api_call_docker_id,omitempty"` // ID of docker user.
	Api_call_name string `json:"api_call_name,omitempty"` // Name of the API operation called.
	Api_call_start string `json:"api_call_start,omitempty"` // Date/time of call start.
}

// Layer represents the Layer schema from the OpenAPI specification
type Layer struct {
	Digest string `json:"digest,omitempty"` // image layer digest
	Instruction string `json:"instruction,omitempty"` // Dockerfile instruction
	Size int `json:"size,omitempty"` // size of the layer
}

// PatchAccessTokenRequest represents the PatchAccessTokenRequest schema from the OpenAPI specification
type PatchAccessTokenRequest struct {
	Is_active bool `json:"is_active,omitempty"`
	Token_label string `json:"token_label,omitempty"`
}

// PostNamespacesDeleteImagesResponseSuccess represents the PostNamespacesDeleteImagesResponseSuccess schema from the OpenAPI specification
type PostNamespacesDeleteImagesResponseSuccess struct {
	Dry_run bool `json:"dry_run,omitempty"` // Whether the request was a dry run or not.
	Metrics map[string]interface{} `json:"metrics,omitempty"`
}

// Scimschema represents the Scimschema schema from the OpenAPI specification
type Scimschema struct {
	Schemas []string `json:"schemas,omitempty"`
	Attributes []Scimschemaparentattribute `json:"attributes,omitempty"`
	Description string `json:"description,omitempty"`
	Id string `json:"id,omitempty"`
	Name string `json:"name,omitempty"`
}

// PostUsersLoginSuccessResponse represents the PostUsersLoginSuccessResponse schema from the OpenAPI specification
type PostUsersLoginSuccessResponse struct {
	Token string `json:"token,omitempty"` // Created authentication token. This token can be used in the HTTP Authorization header as a JWT to authenticate with the Docker Hub APIs.
}

// GetAccessTokensResponse represents the GetAccessTokensResponse schema from the OpenAPI specification
type GetAccessTokensResponse struct {
	Active_count float64 `json:"active_count,omitempty"`
	Count float64 `json:"count,omitempty"`
	Next string `json:"next,omitempty"`
	Previous string `json:"previous,omitempty"`
	Results []interface{} `json:"results,omitempty"`
}

// Restrictedimages represents the Restrictedimages schema from the OpenAPI specification
type Restrictedimages struct {
	Enabled bool `json:"enabled,omitempty"` // Whether or not to restrict image usage for users in the organization.
	Allow_official_images bool `json:"allow_official_images,omitempty"` // Allow usage of official images if "enabled" is `true`.
	Allow_verified_publishers bool `json:"allow_verified_publishers,omitempty"` // Allow usage of verified publisher images if "enabled" is `true`.
}

// Scimresourcetype represents the Scimresourcetype schema from the OpenAPI specification
type Scimresourcetype struct {
	Endpoint string `json:"endpoint,omitempty"`
	Id string `json:"id,omitempty"`
	Name string `json:"name,omitempty"`
	Schema string `json:"schema,omitempty"`
	Schemas []string `json:"schemas,omitempty"`
	Description string `json:"description,omitempty"`
}

// AuditLogAction represents the AuditLogAction schema from the OpenAPI specification
type AuditLogAction struct {
	Name string `json:"name,omitempty"` // Name of audit log action.
	Description string `json:"description,omitempty"` // Description of audit log action.
	Label string `json:"label,omitempty"` // Label for audit log action.
}

// GetAuditActionsResponse represents the GetAuditActionsResponse schema from the OpenAPI specification
type GetAuditActionsResponse struct {
	Actions map[string]interface{} `json:"actions,omitempty"` // Map of audit log actions.
}

// RpcStatus represents the RpcStatus schema from the OpenAPI specification
type RpcStatus struct {
	Code int `json:"code,omitempty"`
	Details []ProtobufAny `json:"details,omitempty"`
	Message string `json:"message,omitempty"`
}

// Scimusername represents the Scimusername schema from the OpenAPI specification
type Scimusername struct {
	Familyname string `json:"familyName,omitempty"`
	Givenname string `json:"givenName,omitempty"`
}

// Tag represents the Tag schema from the OpenAPI specification
type Tag struct {
	Creator int `json:"creator,omitempty"` // ID of the user that pushed the tag
	Full_size int `json:"full_size,omitempty"` // compressed size (sum of all layers) of the tagged image
	Id int `json:"id,omitempty"` // tag ID
	Images Image `json:"images,omitempty"`
	Status string `json:"status,omitempty"` // whether a tag has been pushed to or pulled in the past month
	Tag_last_pulled string `json:"tag_last_pulled,omitempty"` // datetime of last pull
	Last_updater int `json:"last_updater,omitempty"` // ID of the last user that updated the tag
	Name string `json:"name,omitempty"` // name of the tag
	Repository int `json:"repository,omitempty"` // repository ID
	V2 string `json:"v2,omitempty"` // repository API version
	Tag_last_pushed string `json:"tag_last_pushed,omitempty"` // datetime of last push
	Last_updated string `json:"last_updated,omitempty"` // datetime of last update
	Last_updater_username string `json:"last_updater_username,omitempty"` // Hub username of the user that updated the tag
}

// GetNamespaceRepositoryImagesTagsResponse represents the GetNamespaceRepositoryImagesTagsResponse schema from the OpenAPI specification
type GetNamespaceRepositoryImagesTagsResponse struct {
	Next string `json:"next,omitempty"` // Link to the next page if there are more tags.
	Previous string `json:"previous,omitempty"` // Link to the previous page if not on first page.
	Results []map[string]interface{} `json:"results,omitempty"` // The current and historical tags for this image.
	Count int `json:"count,omitempty"` // Total count of tags for this image.
}

// CreateAccessTokenRequest represents the CreateAccessTokenRequest schema from the OpenAPI specification
type CreateAccessTokenRequest struct {
	Scopes []string `json:"scopes"` // Valid scopes: "repo:admin", "repo:write", "repo:read", "repo:public_read"
	Token_label string `json:"token_label"` // Friendly name for you to identify the token.
}

// Scimuser represents the Scimuser schema from the OpenAPI specification
type Scimuser struct {
	Name Scimusername `json:"name,omitempty"`
	Id string `json:"id,omitempty"` // The unique identifier for the user. A v4 UUID.
	Meta map[string]interface{} `json:"meta,omitempty"`
	Username string `json:"userName,omitempty"` // The user's email address. This must be reachable via email.
	Schemas []string `json:"schemas,omitempty"`
	Active bool `json:"active,omitempty"`
	Displayname string `json:"displayName,omitempty"` // The username in Docker. Also known as the "Docker ID".
	Emails []Scimemail `json:"emails,omitempty"`
	Groups []Scimgroup `json:"groups,omitempty"`
}

// AccessToken represents the AccessToken schema from the OpenAPI specification
type AccessToken struct {
	Token_label string `json:"token_label,omitempty"`
	Client_id string `json:"client_id,omitempty"`
	Created_at string `json:"created_at,omitempty"`
	Creator_ua string `json:"creator_ua,omitempty"`
	Last_used string `json:"last_used,omitempty"`
	Creator_ip string `json:"creator_ip,omitempty"`
	Generated_by string `json:"generated_by,omitempty"`
	Scopes []string `json:"scopes,omitempty"`
	Uuid string `json:"uuid,omitempty"`
	Is_active bool `json:"is_active,omitempty"`
	Token string `json:"token,omitempty"`
}

// Scimschemaattribute represents the Scimschemaattribute schema from the OpenAPI specification
type Scimschemaattribute struct {
	Uniqueness string `json:"uniqueness,omitempty"`
	Caseexact bool `json:"caseExact,omitempty"`
	Description string `json:"description,omitempty"`
	Mutability string `json:"mutability,omitempty"`
	Name string `json:"name,omitempty"`
	Returned string `json:"returned,omitempty"`
	Multivalued bool `json:"multiValued,omitempty"`
	Required bool `json:"required,omitempty"`
	TypeField string `json:"type,omitempty"`
}

// CreateAccessTokensResponse represents the CreateAccessTokensResponse schema from the OpenAPI specification
type CreateAccessTokensResponse struct {
	Creator_ua string `json:"creator_ua,omitempty"`
	Last_used string `json:"last_used,omitempty"`
	Creator_ip string `json:"creator_ip,omitempty"`
	Generated_by string `json:"generated_by,omitempty"`
	Scopes []string `json:"scopes,omitempty"`
	Uuid string `json:"uuid,omitempty"`
	Is_active bool `json:"is_active,omitempty"`
	Token string `json:"token,omitempty"`
	Token_label string `json:"token_label,omitempty"`
	Client_id string `json:"client_id,omitempty"`
	Created_at string `json:"created_at,omitempty"`
}
