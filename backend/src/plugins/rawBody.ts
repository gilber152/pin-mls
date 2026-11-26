import fp from 'fastify-plugin';
import type { FastifyPluginAsync } from 'fastify';
import './authTypes.js';

const rawBodyPlugin: FastifyPluginAsync = async (fastify) => {
  if (!fastify.hasRequestDecorator('rawBody')) {
    fastify.decorateRequest('rawBody', undefined);
  }

  fastify.addContentTypeParser(
    'application/json',
    { parseAs: 'buffer' },
    (req, body, done) => {
      const buf = Buffer.isBuffer(body) ? body : Buffer.from(body);
      req.rawBody = buf;
      if (buf.length === 0) {
        done(null, {});
        return;
      }
      try {
        done(null, JSON.parse(buf.toString('utf8')));
      } catch (err) {
        done(err as Error, undefined);
      }
    },
  );

  fastify.addContentTypeParser(
    'application/octet-stream',
    { parseAs: 'buffer' },
    (req, body, done) => {
      const buf = Buffer.isBuffer(body) ? body : Buffer.from(body);
      req.rawBody = buf;
      done(null, buf);
    },
  );
};

export default fp(rawBodyPlugin, {
  name: 'pin-raw-body',
  fastify: '5.x',
});
