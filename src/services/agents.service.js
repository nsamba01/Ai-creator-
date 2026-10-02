/**
 * Agent orchestration registry (CODAGE / TESTS / ANALYSE / SÉCURITÉ / ...).
 *
 * The table `agent_tasks` is the shared work board. This service exposes the
 * catalogue of specialised roles, the task board, and a "next step" indicator
 * that reflects the mandated workflow:
 *   analyse → plan → implémentation → tests → audit indépendant → correction
 *   → tests finaux → rapport → validation humaine
 */
import { badRequest, notFound } from '../utils/errors.js';

export const AGENT_ROLES = [
  { key: 'architecte', name: 'Agent Architecte', mission: 'Analyse l’architecture, propose les modifications et valide les frontières entre frontend/backend/API/base.', permissions: ['agents:read'] },
  { key: 'developpeur', name: 'Agent Développeur', mission: 'Écrit et modifie le code, uniquement dans les fichiers identifiés par le plan.', permissions: ['files:create', 'agents:update'] },
  { key: 'qa', name: 'Agent QA', mission: 'Crée et exécute les tests, mesure la couverture des chemins critiques.', permissions: ['agents:update'] },
  { key: 'securite', name: 'Agent Sécurité', mission: 'Recherche injections, XSS/CSRF, SSRF, CORS, secrets exposés, permissions, Docker, dépendances.', permissions: ['security:read', 'audit:read'] },
  { key: 'reviewer', name: 'Agent Reviewer', mission: 'Second avis indépendant : erreurs du premier diagnostic, hypothèses non vérifiées, régressions, cas limites.', permissions: ['audit:read'] },
  { key: 'integrateur', name: 'Agent Intégrateur', mission: 'Consolide les résultats, vérifie la cohérence des modifications livrées.', permissions: ['agents:update'] },
  { key: 'document', name: 'Agent Documentaire', mission: 'Extraction/analyse PDF, DOCX, XLSX, CSV, JSON, Markdown ; rapports et comparaisons.', permissions: ['documents:analyze'] },
  { key: 'video', name: 'Agent Vidéo', mission: 'Architecture prête pour montage, découpage, sous-titres, transcription (moteur externe à brancher).', permissions: ['urls:analyze'] },
];

export const WORKFLOW = [
  'Inspection du projet',
  'Plan technique',
  'Implémentation',
  'Tests existants',
  'Tests complémentaires',
  'Audit indépendant (second avis)',
  'Corrections',
  'Tests finaux',
  'Rapport + documentation',
  'Validation humaine',
];

export const TASK_STATUSES = ['queued', 'running', 'blocked', 'review', 'done', 'failed', 'cancelled'];
export const TASK_PRIORITIES = ['low', 'normal', 'high', 'critical'];

export function createAgentService({ db, audit }) {
  function list() {
    const rows = db.all(`SELECT agent_role, status, count(*) AS c FROM agent_tasks WHERE TRUE GROUP BY agent_role, status`);
    const byRole = new Map();
    for (const r of rows) {
      if (!byRole.has(r.agent_role)) byRole.set(r.agent_role, { total: 0, counts: {} });
      const e = byRole.get(r.agent_role);
      e.total += r.c;
      e.counts[r.status] = r.c;
    }
    return AGENT_ROLES.map((role) => ({
      ...role,
      active: byRole.get(role.key)?.counts?.running ?? 0,
      queued: byRole.get(role.key)?.counts?.queued ?? 0,
      done: byRole.get(role.key)?.counts?.done ?? 0,
      totalTasks: byRole.get(role.key)?.total ?? 0,
    }));
  }

  function tasks({ status = '', role = '', limit = 50, offset = 0 } = {}) {
    const where = [];
    const params = [];
    if (status && TASK_STATUSES.includes(status)) {
      where.push('status = ?');
      params.push(status);
    }
    if (role && AGENT_ROLES.some((r) => r.key === role)) {
      where.push('agent_role = ?');
      params.push(role);
    }
    const clause = where.length ? `WHERE ${where.join(' AND ')}` : '';
    const total = db.get(`SELECT count(*) AS c FROM agent_tasks ${clause}`, params).c;
    const rows = db.all(
      `SELECT t.*, cu.username AS created_by_name, au.username AS assigned_to_name
         FROM agent_tasks t
         LEFT JOIN users cu ON cu.id = t.created_by
         LEFT JOIN users au ON au.id = t.assigned_to
        ${clause} ORDER BY CASE t.priority WHEN 'critical' THEN 0 WHEN 'high' THEN 1 WHEN 'normal' THEN 2 ELSE 3 END, t.id DESC
        LIMIT ? OFFSET ?`,
      [...params, Math.min(200, Math.max(1, limit)), Math.max(0, offset)],
    );
    return { total, items: rows.map(toDto) };
  }

  function nextRef() {
    const n = db.get(`SELECT count(*) AS c FROM agent_tasks`).c + 1;
    return `T-${String(n).padStart(4, '0')}`;
  }

  function create({ title, agentRole, priority = 'normal', description = '', createdBy = null }) {
    if (!title || title.trim().length < 4) throw badRequest('Titre de tâche requis (4 caractères minimum).');
    if (!AGENT_ROLES.some((r) => r.key === agentRole)) throw badRequest('Rôle d’agent inconnu.');
    if (!TASK_PRIORITIES.includes(priority)) throw badRequest('Priorité invalide.');
    const res = db.run(
      `INSERT INTO agent_tasks (ref, title, agent_role, status, priority, description, created_by) VALUES (?,?,?,?,?,?,?)`,
      [nextRef(), title.trim().slice(0, 200), agentRole, 'queued', priority, String(description ?? '').slice(0, 4000), createdBy],
    );
    const row = db.get(`SELECT * FROM agent_tasks WHERE id = ?`, [res.lastInsertRowid]);
    audit?.record({ actor: { id: createdBy }, action: audit.AUDIT.AGENT_TASK_CREATED, category: 'agents', targetType: 'agent_task', targetId: row.id, detail: { ref: row.ref, agentRole } });
    return toDto(row);
  }

  function update(id, patch, { actor = null } = {}) {
    const row = db.get(`SELECT * FROM agent_tasks WHERE id = ?`, [id]);
    if (!row) throw notFound('Tâche introuvable.');
    const status = patch.status ?? row.status;
    if (!TASK_STATUSES.includes(status)) throw badRequest('Statut invalide.');
    const priority = patch.priority ?? row.priority;
    if (!TASK_PRIORITIES.includes(priority)) throw badRequest('Priorité invalide.');
    db.run(
      `UPDATE agent_tasks SET title = ?, status = ?, priority = ?, description = ?, result_summary = ?, assigned_to = ?, updated_at = ?,
              completed_at = CASE WHEN ? = 'done' THEN ? ELSE NULL END WHERE id = ?`,
      [
        String(patch.title ?? row.title).slice(0, 200),
        status,
        priority,
        String(patch.description ?? row.description).slice(0, 4000),
        String(patch.resultSummary ?? row.result_summary).slice(0, 4000),
        patch.assignedTo === undefined ? row.assigned_to : patch.assignedTo,
        new Date().toISOString(),
        status,
        new Date().toISOString(),
        id,
      ],
    );
    audit?.record({
      actor,
      action: audit.AUDIT.AGENT_TASK_UPDATED,
      category: 'agents',
      targetType: 'agent_task',
      targetId: id,
      detail: { status, priority, from: row.status },
    });
    return toDto(db.get(`SELECT * FROM agent_tasks WHERE id = ?`, [id]));
  }

  function stats() {
    const byStatus = db.all(`SELECT status, count(*) AS c FROM agent_tasks GROUP BY status`);
    return {
      agents: AGENT_ROLES.length,
      total: db.get(`SELECT count(*) AS c FROM agent_tasks`).c,
      byStatus: Object.fromEntries(byStatus.map((r) => [r.status, r.c])),
      roles: AGENT_ROLES.map((r) => r.key),
      workflow: WORKFLOW,
    };
  }

  return { list, tasks, create, update, stats, AGENT_ROLES, WORKFLOW, TASK_STATUSES, TASK_PRIORITIES };
}

function toDto(row) {
  return {
    id: row.id,
    ref: row.ref,
    title: row.title,
    agentRole: row.agent_role,
    status: row.status,
    priority: row.priority,
    description: row.description,
    resultSummary: row.result_summary,
    createdBy: row.created_by,
    createdByName: row.created_by_name ?? null,
    assignedTo: row.assigned_to,
    assignedToName: row.assigned_to_name ?? null,
    createdAt: row.created_at,
    updatedAt: row.updated_at,
    completedAt: row.completed_at,
  };
}

export default createAgentService;
