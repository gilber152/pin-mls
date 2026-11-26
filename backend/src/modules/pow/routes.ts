import type { FastifyInstance } from 'fastify';
import { issuePowChallenge, type PowAction } from '../../infra/pow.js';

interface ChallengeBody {
  action?: unknown;
}

export async function registerPowRoutes(fastify: FastifyInstance): Promise<void> {
  fastify.post<{ Body: ChallengeBody }>('/v1/pow/challenge', async (req, reply) => {
    const action = req.body?.action;
    if (action !== 1 && action !== 2 && action !== 3) {
      return reply.code(400).send({ error: 'INVALID_POW_ACTION' });
    }
    const issued = issuePowChallenge(action as PowAction);
    return reply.code(200).header('Cache-Control', 'no-store').send(issued);
  });
}
