/**
 * Agent / task board routes.
 *
 * `agents:read` is granted to everyone (transparency about what is running),
 * `agents:update` is ADMIN-only (the board can steer work).
 */
import { Router } from 'express';
import { wrap, noStore, pagination } from './_helpers.js';
import { validateBody, S } from '../middleware/validate.js';

export function createAgentRoutes(runtime) {
  const router = Router();
  const { agents } = runtime;
  const { requireAuth, requirePermission } = runtime.middlewares;

  router.get('/', requireAuth, requirePermission('agents:read'), noStore, wrap(async (req, res) => {
    res.json({ agents: agents.list(), workflow: agents.WORKFLOW, stats: agents.stats() });
  }));

  router.get('/tasks', requireAuth, requirePermission('agents:read'), noStore, wrap(async (req, res) => {
    const { limit, offset } = pagination(req.query, { limit: 50, max: 200 });
    res.json(
      agents.tasks({
        limit,
        offset,
        status: String(req.query.status ?? '').slice(0, 16),
        role: String(req.query.role ?? '').slice(0, 24),
      }),
    );
  }));

  router.post('/tasks', requireAuth, requirePermission('agents:update'), noStore, validateBody({
    title: S.text({ min: 4, max: 200, label: 'titre' }),
    agentRole: S.text({ min: 2, max: 24, label: 'rôle', enum: runtime.agents.AGENT_ROLES.map((r) => r.key) }),
    priority: S.text({ max: 12, required: false, default: 'normal', enum: runtime.agents.TASK_PRIORITIES }),
    description: S.text({ min: 3, max: 4000, required: false, default: '' }),
  }), wrap(async (req, res) => {
    const task = agents.create({ ...req.validated, createdBy: req.user.id });
    res.status(201).json({ task });
  }));

  router.patch('/tasks/:id', requireAuth, requirePermission('agents:update'), noStore, validateBody({
    title: S.text({ min: 4, max: 200, required: false }),
    status: S.text({ max: 16, required: false, enum: runtime.agents.TASK_STATUSES }),
    priority: S.text({ max: 12, required: false, enum: runtime.agents.TASK_PRIORITIES }),
    description: S.text({ min: 1, max: 4000, required: false }),
    resultSummary: S.text({ min: 1, max: 4000, required: false }),
    assignedTo: S.id({ required: false }),
  }), wrap(async (req, res) => {
    const task = agents.update(Number(req.params.id), req.validated, { actor: req.user });
    res.json({ task });
  }));

  return router;
}

export default createAgentRoutes;
