package db

import (
	"context"
	"encoding/json"
)

// Explicit projections: never to_jsonb(row) in exported payloads. Raw source rows
// are used only for opaque revision hashes inside PostgreSQL. All relationship
// endpoints must belong to the authorized company's eligible set.
const providerRecordsSQL = `
WITH task_companies AS (
 SELECT id AS task_id,company_id FROM tasks WHERE company_id IS NOT NULL
 UNION SELECT task_id,company_id FROM task_scope WHERE kind='company' AND company_id IS NOT NULL
), own_tasks AS (
 SELECT t.* FROM tasks t WHERE EXISTS(SELECT 1 FROM task_companies c WHERE c.task_id=t.id AND c.company_id=$1)
 AND NOT EXISTS(SELECT 1 FROM task_companies c WHERE c.task_id=t.id AND c.company_id<>$1)
 AND NOT EXISTS(SELECT 1 FROM task_asset_links l JOIN assets a ON a.id=l.asset_id WHERE l.task_id=t.id AND a.company_id IS DISTINCT FROM $1)
 AND NOT EXISTS(SELECT 1 FROM assets a WHERE t.id=ANY(a.task_ids) AND a.company_id IS DISTINCT FROM $1)
), own_assets AS (SELECT * FROM assets WHERE company_id=$1),
 finding_owners AS (
 SELECT f.id,
 COALESCE((SELECT count(*) FROM jsonb_array_elements(CASE WHEN jsonb_typeof(f.asset_ids)='array' THEN f.asset_ids ELSE '[]' END)),0) AS links,
 (SELECT count(*) FROM jsonb_array_elements(CASE WHEN jsonb_typeof(f.asset_ids)='array' THEN f.asset_ids ELSE '[]' END) v JOIN own_assets a ON a.id::text=v#>>'{}') AS own_links
 FROM findings f
), attributable_findings AS (
 SELECT f.* FROM findings f JOIN finding_owners o ON o.id=f.id
 WHERE (EXISTS(SELECT 1 FROM own_tasks t WHERE t.id=f.task_id) OR (f.task_id IS NULL AND o.links>0 AND o.links=o.own_links))
 AND o.links=o.own_links AND jsonb_typeof(f.asset_ids)='array'
), own_findings AS (
 SELECT * FROM attributable_findings WHERE severity IN ('critical','high','medium','low','info','') AND status IN ('pending','in_progress','confirmed','resolved','fixed','false_positive','ignored','duplicate','risk_accepted')
), own_nodes AS (
 SELECT n.* FROM exploration_nodes n JOIN own_tasks t ON t.exploration_id=n.exploration_id
 WHERE NOT EXISTS(SELECT 1 FROM exploration_anchors an LEFT JOIN own_assets a ON a.id=an.asset_id WHERE an.node_id=n.id AND a.id IS NULL)
), base(family,id,payload,deleted) AS (
 SELECT 'company',c.id::text,jsonb_build_object('source_revision',encode(sha256(convert_to(to_jsonb(c)::text,'UTF8')),'hex'),'created_at',c.created_at,'updated_at',c.updated_at,'name',c.name,'nkey',c.nkey),false FROM companies c WHERE c.id=$1
 UNION ALL
 SELECT 'scope',s.id::text,jsonb_build_object('source_revision',encode(sha256(convert_to(to_jsonb(s)::text,'UTF8')),'hex'),'kind',s.kind,'created_at',s.created_at,'domain',s.domain,'net',s.net::text,'value',s.value,'raw',s.raw,'reason',s.reason),false FROM company_scope s WHERE s.company_id=$1
 UNION ALL
 SELECT 'asset',a.id::text,jsonb_build_object('source_revision',encode(sha256(convert_to(to_jsonb(a)::text,'UTF8')),'hex'),'type',a.type,'company_source',a.company_source,'port',a.port,'status_code',a.status_code,'content_length',a.content_length,'created_at',a.created_at,'updated_at',a.updated_at,'last_seen',a.last_seen,'domain',a.domain,'root_domain',a.root_domain,'ip',a.ip,'c_segment',a.c_segment::text,'icp',a.icp,'bound_domains',a.bound_domains,'open_ports',a.open_ports,'record_type',a.record_type,'record_value',a.record_value,'bundle_id',a.bundle_id,'app_name',a.app_name,'category',a.category,'app_description',a.app_description,'app_icp',a.app_icp,'url',a.url,'service_type',a.service_type,'service_name',a.service_name,'favicon_mmh3',a.favicon_mmh3,'page_title',a.page_title,'technologies',a.technologies,'method',a.method,'authentication_present',cardinality(a.auth)>0,'params',a.params,'extra',a.extra,'field_exclusions',jsonb_build_array('authentication_values','parameter_values','unsupported_arbitrary_metadata')),false FROM own_assets a
 UNION ALL
 SELECT 'task',t.id::text,jsonb_build_object('source_revision',encode(sha256(convert_to(to_jsonb(t)::text,'UTF8')),'hex'),'status',t.status,'exploration_id',t.exploration_id,'coverage_enabled',t.coverage_enabled,'created_at',t.created_at,'updated_at',t.updated_at,'archived_at',t.archived_at,'deleted_at',t.deleted_at,'name',t.name,'description',t.description,'goal',t.goal),t.deleted_at IS NOT NULL FROM own_tasks t
 UNION ALL
 SELECT 'task_scope',s.id::text,jsonb_build_object('source_revision',encode(sha256(convert_to(to_jsonb(s)::text,'UTF8')),'hex'),'task_id',s.task_id,'kind',s.kind,'source',s.source,'domain',s.domain,'net',s.net::text,'value',s.value,'reason',s.reason),false FROM task_scope s JOIN own_tasks t ON t.id=s.task_id WHERE s.company_id IS NULL OR s.company_id=$1
 UNION ALL
 SELECT 'finding',f.id::text,jsonb_build_object('source_revision',encode(sha256(convert_to(to_jsonb(f)::text,'UTF8')),'hex'),'task_id',f.task_id,'node_id',CASE WHEN EXISTS(SELECT 1 FROM own_nodes n WHERE n.id=f.node_id) THEN f.node_id END,'asset_ids',f.asset_ids,'severity',f.severity,'status',f.status,'evidence_version',f.evidence_version,'report_evidence_version',f.report_evidence_version,'created_at',f.created_at,'name',f.name,'vulnclass',f.vulnclass,'summary',f.summary,'worker',f.worker),false FROM own_findings f
 UNION ALL
 SELECT 'report',f.id::text,jsonb_build_object('source_revision',encode(sha256(convert_to(f.report,'UTF8')),'hex'),'finding_id',f.id,'evidence_version',f.evidence_version,'report_evidence_version',f.report_evidence_version,'present',f.report<>'','body',left(f.report,262145),'detail_policy','automatic_redacted'),false FROM own_findings f
 UNION ALL
 SELECT 'evidence',f.id::text,jsonb_build_object('source_revision',encode(sha256(convert_to(f.evidence,'UTF8')),'hex'),'finding_id',f.id,'version',f.evidence_version,'present',f.evidence<>'','body',left(f.evidence,262145),'detail_policy','automatic_redacted'),false FROM own_findings f
 UNION ALL
 SELECT 'retest',r.id::text,jsonb_build_object('source_revision',encode(sha256(convert_to(to_jsonb(r)::text,'UTF8')),'hex'),'finding_id',r.finding_id,'status',r.status,'verdict',r.verdict,'created_at',r.created_at,'started_at',r.started_at,'finished_at',r.finished_at,'notes',r.notes,'summary',r.summary,'body',left(r.evidence,262145),'error',r.error,'detail_policy','automatic_redacted','field_exclusions',jsonb_build_array('historical_snapshot_unattributed_embedded_records')),false FROM finding_retests r JOIN own_findings f ON f.id=r.finding_id
 UNION ALL
 SELECT 'evidence_reference',b.id::text,jsonb_build_object('source_revision',encode(sha256(convert_to(to_jsonb(b)::text||to_jsonb(s)::text,'UTF8')),'hex'),'finding_id',b.finding_id,'evidence_version',f.evidence_version,'snapshot_id',s.id,'request_checksum',CASE WHEN s.req_hash ~ '^[0-9a-f]{64}$' THEN s.req_hash END,'response_checksum',CASE WHEN s.resp_hash ~ '^[0-9a-f]{64}$' THEN s.resp_hash END,'request_length',s.req_len,'response_length',s.resp_len,'position',b.position,'created_at',s.created_at,'url',s.url,'method',s.method,'status_code',s.status,'content_type',s.content_type,'role',b.role,'note',b.note,'field_exclusions',jsonb_build_array('raw_traffic_headers_and_bodies')),false FROM finding_traffic_bindings b JOIN own_findings f ON f.id=b.finding_id JOIN traffic_evidence_snapshots s ON s.id=b.snapshot_id
 UNION ALL
 SELECT CASE WHEN n.kind='goal' THEN 'goal' ELSE 'research_node' END,n.id::text,jsonb_build_object('source_revision',encode(sha256(convert_to(to_jsonb(n)::text,'UTF8')),'hex'),'exploration_id',n.exploration_id,'kind',n.kind,'state',n.state,'content_version',n.content_version,'created_at',n.created_at,'updated_at',n.updated_at,'research',n.payload,'origin',n.origin),n.state='deleted' FROM own_nodes n
 UNION ALL
 SELECT 'constraint',c.id::text,jsonb_build_object('source_revision',encode(sha256(convert_to(to_jsonb(c)::text,'UTF8')),'hex'),'exploration_id',c.exploration_id,'kind',c.kind,'created_at',c.created_at,'updated_at',c.updated_at,'text',c.text,'origin',c.origin),false FROM task_constraints c JOIN own_tasks t ON t.exploration_id=c.exploration_id
 UNION ALL
 SELECT 'research_edge',e.exploration_id||':'||e.src_id||':'||e.rel||':'||e.dst_id,jsonb_build_object('exploration_id',e.exploration_id,'src_id',e.src_id,'rel',e.rel,'dst_id',e.dst_id,'created_at',e.created_at),false FROM exploration_edges e JOIN own_nodes src ON src.id=e.src_id JOIN own_nodes dst ON dst.id=e.dst_id
 UNION ALL
 SELECT 'coverage_anchor',a.node_id||':'||a.asset_id,jsonb_build_object('node_id',a.node_id,'asset_id',a.asset_id),false FROM exploration_anchors a JOIN own_nodes n ON n.id=a.node_id JOIN own_assets s ON s.id=a.asset_id
 UNION ALL
 SELECT 'lineage',l.task_id||':'||l.source_task_id,jsonb_build_object('task_id',l.task_id,'source_task_id',l.source_task_id,'created_at',l.created_at),false FROM task_relations l JOIN own_tasks t ON t.id=l.task_id JOIN own_tasks src ON src.id=l.source_task_id
 UNION ALL
 SELECT 'task_asset',l.task_id||':'||l.asset_id,jsonb_build_object('task_id',l.task_id,'asset_id',l.asset_id,'source_node_id',CASE WHEN EXISTS(SELECT 1 FROM own_nodes n WHERE n.id=l.source_node_id) THEN l.source_node_id END,'created_at',l.created_at,'updated_at',l.updated_at,'source_summary',l.source_summary),false FROM task_asset_links l JOIN own_tasks t ON t.id=l.task_id JOIN own_assets a ON a.id=l.asset_id
 UNION ALL
 SELECT 'activity',a.id::text,jsonb_build_object('exploration_id',a.exploration_id,'node_id',CASE WHEN EXISTS(SELECT 1 FROM own_nodes n WHERE n.id=a.node_id) THEN a.node_id END,'is_error',a.is_error,'created_at',a.created_at,'kind',a.kind,'tool',a.tool,'summary',a.summary,'field_exclusions',jsonb_build_array('tool_inputs_outputs_metadata_and_transcripts')),false FROM activity a JOIN own_tasks t ON t.exploration_id=a.exploration_id
 UNION ALL
 SELECT 'archive',a.id::text,jsonb_build_object('task_id',a.task_id,'content_excluded',true),false FROM task_archives a JOIN own_tasks t ON t.id=a.task_id
 UNION ALL
 SELECT 'rejected','task:'||t.id,jsonb_build_object('family','task','reason','ambiguous_company_attribution'),false FROM tasks t WHERE EXISTS(SELECT 1 FROM task_companies c WHERE c.task_id=t.id AND c.company_id=$1) AND NOT EXISTS(SELECT 1 FROM own_tasks o WHERE o.id=t.id)
 UNION ALL
 SELECT 'rejected','finding:'||f.id,jsonb_build_object('family','finding','reason',CASE WHEN EXISTS(SELECT 1 FROM attributable_findings af WHERE af.id=f.id) THEN 'invalid_source_enum' ELSE 'ambiguous_company_attribution' END),false FROM findings f JOIN finding_owners o ON o.id=f.id WHERE (o.own_links>0 OR EXISTS(SELECT 1 FROM task_companies c WHERE c.task_id=f.task_id AND c.company_id=$1)) AND NOT EXISTS(SELECT 1 FROM own_findings own WHERE own.id=f.id)
), publications AS (
 SELECT p.* FROM provider_publications p JOIN base b ON b.family=p.family AND b.id=p.record_id AND b.payload->>'source_revision'=p.source_revision
 WHERE p.company_id=$1 AND p.withdrawn_at IS NULL AND NOT b.deleted
)
SELECT family,id,payload,deleted FROM base
UNION ALL
SELECT 'publication',p.id,jsonb_build_object('family',p.family,'record_id',p.record_id,'source_revision',p.source_revision,'content',p.content,'checksum',p.checksum,'approved_at',p.approved_at),false FROM publications p
UNION ALL
SELECT 'rejected','publication:'||p.id,jsonb_build_object('family','publication','reason','source_changed_or_absent'),false FROM provider_publications p WHERE p.company_id=$1 AND p.withdrawn_at IS NULL AND NOT EXISTS(SELECT 1 FROM publications ok WHERE ok.id=p.id)
ORDER BY 1,2
`

// Source revision matching is shared by snapshot exports and on-demand retrieval.
func (d *DB) ProviderPublication(ctx context.Context, company int64, id string) (json.RawMessage, error) {
	var b []byte
	err := d.QueryRowContext(ctx, `SELECT payload FROM (`+providerRecordsSQL+`) q WHERE family='publication' AND id=$2`, company, id).Scan(&b)
	if err != nil {
		return nil, err
	}
	safe, err := ProviderPayload("publication", b, true)
	return json.RawMessage(safe), err
}

func (d *DB) ProviderSourceRecord(ctx context.Context, company int64, family, id string) (json.RawMessage, error) {
	var b []byte
	err := d.QueryRowContext(ctx, `SELECT payload FROM (`+providerRecordsSQL+`) q WHERE family=$2 AND id=$3 AND family NOT IN ('publication','rejected') AND NOT deleted`, company, family, id).Scan(&b)
	return json.RawMessage(b), err
}
