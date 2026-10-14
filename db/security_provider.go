package db

import (
	"log"
	"regexp"

	"github.com/Autumn-27/artex/locale"
)

// MCPValidationError identifies rejected configuration, not a database outage.
type MCPValidationError struct {
	Code string
}

func (e *MCPValidationError) Error() string {
	return e.MessageForLanguage(locale.En)
}

func (e *MCPValidationError) MessageForLanguage(lang locale.Lang) string {
	return locale.T(lang, "mcp.provider."+e.Code)
}

var sourceRevisionSHA = regexp.MustCompile(`^[0-9a-f]{40}$`)

func validateMCPProvider(m *MCPServer) error {
	switch m.ProviderKind {
	case "", "yeepforge", "adstrike":
	default:
		return &MCPValidationError{Code: "kind"}
	}
	if m.SourceRevision != "" && !sourceRevisionSHA.MatchString(m.SourceRevision) {
		return &MCPValidationError{Code: "revision"}
	}
	if m.ProviderKind != "" && (m.Transport != "stdio" || m.URL != "" || m.Insecure) {
		return &MCPValidationError{Code: "stdio"}
	}
	return nil
}

// Templates are seeded in schema.sql. Report occupied labels without changing
// operator rows or making database initialization fail.
func (d *DB) reportMCPProviderCollisions() error {
	rows, err := d.Query(`SELECT name FROM mcp_servers
WHERE (name='YeepForge' AND provider_kind<>'yeepforge')
   OR (name='AdStrike' AND provider_kind<>'adstrike') ORDER BY name`)
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		var name string
		if err := rows.Scan(&name); err != nil {
			return err
		}
		log.Printf(locale.T(locale.ServerDefault(), "mcp.provider.collision"), name)
	}
	return rows.Err()
}

func init() {
	locale.RegisterAll(map[string]map[locale.Lang]string{
		"mcp.provider.kind": {
			locale.En:     "Provider kind must be empty, yeepforge, or adstrike.",
			locale.Ko:     "제공자 종류는 비어 있거나 yeepforge 또는 adstrike여야 합니다.",
			locale.ZhHans: "提供方类型必须为空、yeepforge 或 adstrike。",
		},
		"mcp.provider.revision": {
			locale.En:     "Source revision must be empty or a 40-character lowercase SHA-1.",
			locale.Ko:     "소스 리비전은 비어 있거나 40자의 소문자 SHA-1이어야 합니다.",
			locale.ZhHans: "源码修订版本必须为空或 40 个字符的小写 SHA-1。",
		},
		"mcp.provider.stdio": {
			locale.En:     "Catalog providers require stdio transport, no URL, and TLS verification enabled.",
			locale.Ko:     "카탈로그 제공자는 stdio 전송을 사용하고 URL이 없어야 하며 TLS 검증을 비활성화할 수 없습니다.",
			locale.ZhHans: "目录提供方必须使用 stdio 传输、不设置 URL，且不得禁用 TLS 验证。",
		},
		"mcp.provider.identity": {
			locale.En:     "Provider identity cannot be changed; the server must still exist.",
			locale.Ko:     "제공자 식별 정보는 변경할 수 없으며 서버가 존재해야 합니다.",
			locale.ZhHans: "提供方标识不可更改，且服务器必须仍然存在。",
		},
		"mcp.provider.collision": {
			locale.En:     "Catalog provider template %s was not seeded because its name is already in use; the existing server was preserved.",
			locale.Ko:     "이름이 이미 사용 중이므로 카탈로그 제공자 템플릿 %s를 추가하지 않았습니다. 기존 서버는 그대로 유지되었습니다.",
			locale.ZhHans: "目录提供方模板 %s 的名称已被占用，因此未添加；现有服务器已保留。",
		},
	})
}
