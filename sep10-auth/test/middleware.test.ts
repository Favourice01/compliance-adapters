import { Keypair } from '@stellar/stellar-sdk';
import type { NextFunction, Request, Response } from 'express';
import { createSep10Middleware } from '../src/middleware';
import { VerifyChallengeOptions } from '../src/verify';

const options: VerifyChallengeOptions = {
  serverAccountId: Keypair.random().publicKey(),
  homeDomains: 'example.com',
  webAuthDomain: 'example.com',
};

function makeReq(authHeader: string | undefined): Request {
  return {
    header: (name: string) => (name === 'Authorization' ? authHeader : undefined),
  } as unknown as Request;
}

function makeRes(): Response {
  const res = {} as Response;
  res.status = jest.fn().mockReturnValue(res);
  res.json = jest.fn().mockReturnValue(res);
  return res;
}

describe('createSep10Middleware - malformed Authorization header', () => {
  it.each([
    ['a non-Bearer scheme', 'Basic abc123'],
    ['an empty header', ''],
    ['Bearer with no token', 'Bearer'],
    ['Bearer with only trailing whitespace', 'Bearer '],
    ['a header with no Authorization at all', undefined],
  ])('returns 401 with "missing bearer token" for %s', (_description, authHeader) => {
    const middleware = createSep10Middleware(options);
    const req = makeReq(authHeader);
    const res = makeRes();
    const next = jest.fn() as unknown as NextFunction;

    middleware(req, res, next);

    expect(res.status).toHaveBeenCalledWith(401);
    expect(res.json).toHaveBeenCalledWith({
      error: 'unauthorized',
      reason: 'missing bearer token',
    });
    expect(next).not.toHaveBeenCalled();
  });
});

describe('createSep10Middleware - domain format validation', () => {
  it.each(['https://example.com', 'example.com/'])('rejects homeDomains %p', (bad) => {
    expect(() => createSep10Middleware({ ...options, homeDomains: bad })).toThrow(
      /bare domain/,
    );
  });

  it('rejects a non-bare webAuthDomain', () => {
    expect(() =>
      createSep10Middleware({ ...options, webAuthDomain: ['example.com', 'http://x.com'] }),
    ).toThrow(/bare domain/);
  });
});
