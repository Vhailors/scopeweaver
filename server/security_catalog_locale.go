package server

import "github.com/Autumn-27/artex/locale"

func init() {
	locale.RegisterAll(map[string]map[locale.Lang]string{
		"security.catalog.description": {
			locale.En:     "Read curated report profiles, visible analysis skills, and cached catalog status without contacting providers.",
			locale.Ko:     "제공자에 연결하지 않고 엄선된 보고서 프로필, 표시 가능한 분석 스킬 및 캐시된 카탈로그 상태를 읽습니다.",
			locale.ZhHans: "读取精选报告配置、可见分析技能和缓存目录状态，不联系提供方。",
		},
		"security.catalog.producer_parameter": {
			locale.En:     "Optional producer identifier; omit to list all three report profiles.",
			locale.Ko:     "선택적 제공자 식별자입니다. 생략하면 세 가지 보고서 프로필을 모두 나열합니다.",
			locale.ZhHans: "可选的提供方标识；省略时列出全部三种报告配置。",
		},
		"security.catalog.disabled": {
			locale.En:     "Security report integration is disabled.",
			locale.Ko:     "보안 보고서 통합이 비활성화되어 있습니다.",
			locale.ZhHans: "安全报告集成已禁用。",
		},
		"security.catalog.not_bound": {
			locale.En:     "The security catalog helper is not enabled for this agent.",
			locale.Ko:     "이 에이전트에는 보안 카탈로그 도우미가 활성화되어 있지 않습니다.",
			locale.ZhHans: "此代理未启用安全目录辅助工具。",
		},
		"security.catalog.invalid_request": {
			locale.En:     "Use only an optional supported producer identifier.",
			locale.Ko:     "지원되는 제공자의 선택적 식별자만 사용하세요.",
			locale.ZhHans: "仅可使用受支持的可选提供方标识。",
		},
		"security.catalog.explicit_only": {
			locale.En:     "Catalog providers allow only explicit authenticated catalog refresh.",
			locale.Ko:     "카탈로그 제공자는 인증된 사용자의 명시적 카탈로그 새로 고침만 허용합니다.",
			locale.ZhHans: "目录提供方仅允许经过身份验证的显式目录刷新。",
		},
		"security.catalog.not_ready": {
			locale.En:     "Enable and configure the catalog provider before refreshing.",
			locale.Ko:     "새로 고침 전에 카탈로그 제공자를 활성화하고 설정하세요.",
			locale.ZhHans: "刷新前请启用并配置目录提供方。",
		},
		"security.catalog.stale": {
			locale.En:     "Provider configuration changed during refresh; the catalog was not published.",
			locale.Ko:     "새로 고침 중 제공자 설정이 변경되어 카탈로그를 저장하지 않았습니다.",
			locale.ZhHans: "刷新期间提供方配置已更改；目录未发布。",
		},
		"security.catalog.unavailable": {
			locale.En:     "Catalog discovery is unavailable or returned invalid metadata.",
			locale.Ko:     "카탈로그를 검색할 수 없거나 반환된 메타데이터가 올바르지 않습니다.",
			locale.ZhHans: "目录发现不可用或返回了无效的元数据。",
		},
	})
}
