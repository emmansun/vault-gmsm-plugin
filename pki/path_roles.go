package pki

import (
	"context"
	"strings"

	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
)

// pathRoles handles one role. A role is the only policy a caller has to write
// before issuing: it decides which names are allowed, which usages the
// certificate carries and how long it lives.
func (b *backend) pathRoles() *framework.Path {
	fields := roleFieldSchemas()
	fields["name"] = &framework.FieldSchema{
		Type:        framework.TypeString,
		Description: "Name of the role.",
	}

	return &framework.Path{
		Pattern: "roles/" + framework.GenericNameRegex("name") + "$",

		DisplayAttrs: &framework.DisplayAttributes{
			OperationPrefix: operationPrefix + "-role",
		},

		Fields: fields,

		Callbacks: map[logical.Operation]framework.OperationFunc{
			logical.UpdateOperation: b.pathRoleWrite,
			logical.PatchOperation:  b.pathRolePatch,
			logical.ReadOperation:   b.pathRoleRead,
			logical.DeleteOperation: b.pathRoleDelete,
		},

		HelpSynopsis:    pathRolesHelpSyn,
		HelpDescription: pathRolesHelpDesc,
	}
}

// pathRolesList lists the roles of the mount.
func (b *backend) pathRolesList() *framework.Path {
	return &framework.Path{
		Pattern: "roles/?$",

		DisplayAttrs: &framework.DisplayAttributes{
			OperationPrefix: operationPrefix + "-roles",
			OperationVerb:   "list",
		},

		Callbacks: map[logical.Operation]framework.OperationFunc{
			logical.ListOperation: b.pathRoleList,
		},

		HelpSynopsis:    pathRolesListHelpSyn,
		HelpDescription: pathRolesListHelpDesc,
	}
}

// pathRoleWrite creates a role from the defaults or replaces an existing one
// wholesale. Fields the request leaves out fall back to the default, which is
// what makes POST the "set the whole policy" operation.
func (b *backend) pathRoleWrite(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	name := strings.TrimSpace(d.Get("name").(string))
	if name == "" {
		return logical.ErrorResponse("a role name is required"), logical.ErrInvalidRequest
	}

	role := newRole()
	applyRoleFields(role, d)

	if err := validateRole(role); err != nil {
		return logical.ErrorResponse(err.Error()), logical.ErrInvalidRequest
	}

	if err := putJSON(ctx, req.Storage, rolePrefix+name, role); err != nil {
		return nil, err
	}

	return roleWarnings(role), nil
}

// pathRolePatch changes only the fields the request carries, which is what
// lets an operator adjust one setting without restating the whole policy.
func (b *backend) pathRolePatch(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	name := strings.TrimSpace(d.Get("name").(string))
	if name == "" {
		return logical.ErrorResponse("a role name is required"), logical.ErrInvalidRequest
	}

	role, err := b.role(ctx, req.Storage, name)
	if err != nil {
		return nil, err
	}
	if role == nil {
		// A patch of a role that does not exist is a miss, not a bad request.
		return nil, nil
	}

	applyRoleFields(role, d)

	if err := validateRole(role); err != nil {
		return logical.ErrorResponse(err.Error()), logical.ErrInvalidRequest
	}

	if err := putJSON(ctx, req.Storage, rolePrefix+name, role); err != nil {
		return nil, err
	}

	return roleWarnings(role), nil
}

func (b *backend) pathRoleRead(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	name := strings.TrimSpace(d.Get("name").(string))
	if name == "" {
		return logical.ErrorResponse("a role name is required"), logical.ErrInvalidRequest
	}

	role, err := b.role(ctx, req.Storage, name)
	if err != nil {
		return nil, err
	}
	if role == nil {
		return nil, nil
	}

	response := &logical.Response{Data: roleData(role)}
	if role.GenerateLease {
		response.Warnings = append(response.Warnings, generateLeaseWarning)
	}

	return response, nil
}

func (b *backend) pathRoleDelete(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	name := strings.TrimSpace(d.Get("name").(string))
	if name == "" {
		return logical.ErrorResponse("a role name is required"), logical.ErrInvalidRequest
	}

	if err := req.Storage.Delete(ctx, rolePrefix+name); err != nil {
		return nil, err
	}

	return nil, nil
}

func (b *backend) pathRoleList(ctx context.Context, req *logical.Request, _ *framework.FieldData) (*logical.Response, error) {
	names, err := req.Storage.List(ctx, rolePrefix)
	if err != nil {
		return nil, err
	}

	return logical.ListResponse(names), nil
}

// generateLeaseWarning is the answer to a role that asks for leases: the field
// is kept so a configuration from the PKI engine still applies, but nothing in
// this mount expires.
const generateLeaseWarning = "generate_lease is accepted for compatibility but leases are not implemented; certificates keep their own expiration instead"

func roleWarnings(role *roleEntry) *logical.Response {
	if !role.GenerateLease {
		return nil
	}

	return &logical.Response{Warnings: []string{generateLeaseWarning}}
}

const pathRolesHelpSyn = `Manage the issuing policies of the mount`

const pathRolesHelpDesc = `
A role is a named policy: the names it may issue for, the key and extended key
usages the certificate carries, and how long it lives. Certificates are
requested with issue/:name or sign/:name, and both refuse anything the role does
not allow. Writing a role replaces it as a whole; patch changes only the fields
of the request; delete removes it without touching the certificates already
issued.
`

const pathRolesListHelpSyn = `List the roles of the mount`

const pathRolesListHelpDesc = `
Lists the name of every role defined in this mount. A role that does not appear
here cannot issue a certificate.
`
