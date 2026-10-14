package server

import "github.com/Autumn-27/artex/locale"

func init() {
	locale.RegisterAll(map[string]map[locale.Lang]string{
		"security.assessment.assessment_unauthorized": {
			locale.En:     "Authentication is required to access assessment reports.",
			locale.Ko:     "평가 보고서에 접근하려면 인증이 필요합니다.",
			locale.ZhHans: "访问评估报告需要身份验证。",
		},
		"security.assessment.assessment_reports_disabled": {
			locale.En:     "Security report intake is disabled.",
			locale.Ko:     "보안 보고서 가져오기가 비활성화되어 있습니다.",
			locale.ZhHans: "安全报告导入已禁用。",
		},
		"security.assessment.assessment_task_unavailable": {
			locale.En:     "The task is unavailable.",
			locale.Ko:     "작업을 사용할 수 없습니다.",
			locale.ZhHans: "任务不可用。",
		},
		"security.assessment.assessment_input_too_large": {
			locale.En:     "The complete JSON request must not exceed 1 MiB.",
			locale.Ko:     "전체 JSON 요청은 1 MiB를 초과할 수 없습니다.",
			locale.ZhHans: "完整的 JSON 请求不得超过 1 MiB。",
		},
		"security.assessment.assessment_content_type": {
			locale.En:     "Send an uncompressed application/json request.",
			locale.Ko:     "압축되지 않은 application/json 요청을 보내세요.",
			locale.ZhHans: "请发送未压缩的 application/json 请求。",
		},
		"security.assessment.assessment_invalid_request": {
			locale.En:     "The assessment request is malformed or exceeds a structural limit.",
			locale.Ko:     "평가 요청의 형식이 잘못되었거나 구조 제한을 초과했습니다.",
			locale.ZhHans: "评估请求格式错误或超出结构限制。",
		},
		"security.assessment.assessment_unsupported_producer": {
			locale.En:     "The report producer is unsupported.",
			locale.Ko:     "지원되지 않는 보고서 제공자입니다.",
			locale.ZhHans: "不支持此报告提供方。",
		},
		"security.assessment.assessment_unsupported_profile": {
			locale.En:     "The supplied report profile is unsupported.",
			locale.Ko:     "제공된 보고서 프로필은 지원되지 않습니다.",
			locale.ZhHans: "不支持所提供的报告配置。",
		},
		"security.assessment.assessment_unavailable": {
			locale.En:     "Assessment report storage is temporarily unavailable.",
			locale.Ko:     "평가 보고서 저장소를 일시적으로 사용할 수 없습니다.",
			locale.ZhHans: "评估报告存储暂时不可用。",
		},
	})
}
